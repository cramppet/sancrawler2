package main

/* SANCrawler is a tool designed to enumerate linked x509 certificates based
 * on shared metadata. Traditional approaches to using x509 data focused on
 * linking based on shared apex domain, but in practice, many different fields
 * exist and are actively used by corporations. SANCrawler implements two such
 * approaches: strict organization search, and general keyword searches matching
 * on any field.
 */

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	// Lets hope this one works better than psycopg2
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

// Data format used by crawlers, tells them which CA they are working on and where the
// bounds of their search are. start and stop usually only come into effect when the
// company is large.
type crawlerData struct {
	caID  int
	start int
	stop  int
}

/* getNames: Retrieves the common names and subject alternative names (SANs)
 * from the postgres instance run by crt.sh, you can find details about their
 * complicated database schema here: https://github.com/crtsh/certwatch_db
 */
func getNames(query string, org string, inChan chan crawlerData, outChan chan string, stopChan chan bool) {
	connStr := "host=crt.sh user=guest dbname=certwatch binary_parameters=yes"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	for {
		select {
		case <-stopChan:
			db.Close()
			return
		case tmpData := <-inChan:
			// offset determines pagination of records from crt.sh.
			// count is how many records we actually read each time.
			for offset, count := tmpData.start, 0; ; offset += count {
				count = 0

				rows, err := db.Query(query, tmpData.caID, org, offset)
				if err != nil {
					log.Fatal(err)
					panic(err)
				}

				// Scan through the records returned and keep track of the information we
				// actually care about. We don't care about ID, but need it since doing an
				// ORDER BY on strings is slow and we need an ORDER BY so we can use LIMIT
				// and OFFSET. I also suck at SQL, so keep that in mind.
				for rows.Next() {
					var (
						ID   int
						name string
					)

					// Note: Some of these results may not be actual domains, recall these are
					// just common names and SANs. They only have to be resolvable/accessible for
					// whatever system is using them. This means you may find internal domain names
					// as SANs that aren't fully qualified. You are very likely to encounter wildcard
					// entires too.

					if err := rows.Scan(&ID, &name); err != nil {
						log.Fatal(err)
					}

					count++

					// Make sure to lowercase to avoid duplicates based on mixed cases

					outChan <- strings.ToLower(name)
				}

				// Bail out if we're done
				if count == 0 {
					break
				}
			}
			break
		default:
			continue
		}
	}
}

func loadCrawlerData(orgname string, sanChan chan crawlerData, cnChan chan crawlerData) int {
	// We need to group all of the certificates by CA. Then we will partition those results
	// into the blocks of crawler data that will get used by other functions.

	numTotalCerts := 0
	numCrawlers := 0

	query := `
	SELECT ci.ISSUER_CA_ID, count(DISTINCT ci.CERTIFICATE_ID)
	 FROM ca, certificate_identity ci
	 WHERE ci.ISSUER_CA_ID = ca.ID AND
				lower(ci.NAME_VALUE) = lower($1)
	 GROUP BY ci.ISSUER_CA_ID;`

	space := regexp.MustCompile(`\s+`)
	query = strings.Replace(query, "\n", " ", -1)
	query = space.ReplaceAllString(query, " ")

	// Make database connection

	connStr := "host=crt.sh user=guest dbname=certwatch"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Pull the results

	rows, err := db.Query(query, orgname)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	for rows.Next() {
		var (
			caID     int
			numCerts int
		)

		if err := rows.Scan(&caID, &numCerts); err != nil {
			log.Fatal(err)
		}

		var tmpData crawlerData
		tmpData.caID = caID
		tmpData.start = 0
		tmpData.stop = numCerts

		sanChan <- tmpData
		cnChan <- tmpData
		numTotalCerts += numCerts
	}

	// How many crawlers will we need for this run? Note this will always
	// be an even number since we have 1 crawler for each name type: SAN, CN.

	if numTotalCerts < 10000 {
		numCrawlers = 1
	} else {
		numCrawlers = (numTotalCerts / 10000)
	}

	db.Close()
	return numCrawlers
}

/* getDomainsByKeyword: Get all the names belonging to a certain organization.
 */
func getDomainsByKeyword(orgname string) map[string]int {
	ret := make(map[string]int)

	// I have never liked SQL and these queries are probably shit, but they return
	// results faster than any of the others I tried by *a lot* and I have no
	// idea why.

	sanQuery := `
	SELECT c.ID, x509_altNames(c.CERTIFICATE, 2, TRUE)
	FROM certificate c WHERE c.ID IN (
		SELECT DISTINCT ci.CERTIFICATE_ID
		 FROM certificate_identity ci
		 WHERE ci.ISSUER_CA_ID = $1 AND
					 lower(ci.NAME_VALUE) = lower($2)
	 )
	ORDER BY c.ID DESC OFFSET $3 LIMIT 2000;
	`

	cnQuery := `
	SELECT c.ID, x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE)
	FROM certificate c WHERE c.ID IN (
		SELECT DISTINCT ci.CERTIFICATE_ID
		 FROM certificate_identity ci
		 WHERE ci.ISSUER_CA_ID = $1 AND
					 lower(ci.NAME_VALUE) = lower($2)
	 )
	ORDER BY c.ID DESC OFFSET $3 LIMIT 2000;
	`

	space := regexp.MustCompile(`\s+`)
	sanQuery = strings.Replace(sanQuery, "\n", " ", -1)
	sanQuery = space.ReplaceAllString(sanQuery, " ")
	cnQuery = strings.Replace(cnQuery, "\n", " ", -1)
	cnQuery = space.ReplaceAllString(cnQuery, " ")

	// Channels for I/O between goroutines. Goroutines will read from either sanChan or
	// cnChan and then put their discovered domains into domainChan. They will begin
	// terminating when doneChan becomes populated.

	sanChan := make(chan crawlerData, 10000)
	cnChan := make(chan crawlerData, 10000)
	domainChan := make(chan string, 10000)
	numCrawlers := loadCrawlerData(orgname, sanChan, cnChan)
	doneChan := make(chan bool, numCrawlers*2)

	for i := 0; i < numCrawlers; i++ {
		go getNames(sanQuery, orgname, sanChan, domainChan, doneChan)
		go getNames(cnQuery, orgname, cnChan, domainChan, doneChan)
	}

	// Keep waiting until both input channels drain.
	// Keep track of the values spewing out.

	for len(sanChan) > 0 || len(cnChan) > 0 {
		select {
		case tmp := <-domainChan:
			ret[tmp] = 0
			break
		default:
			continue
		}
	}

	// Allow for goroutines to start exiting

	for i := 0; i < numCrawlers*2; i++ {
		doneChan <- true
	}

	// Read until both of the other channels finish draining

	for len(doneChan) > 0 || len(domainChan) > 0 {
		select {
		case tmp := <-domainChan:
			ret[tmp] = 0
			break
		default:
			continue
		}
	}

	return ret
}

/* tryExtractOrg: Attempts to automatically extract the organization field from
 * any x509 certificates detected from trying a TLS connection to the URL specified.
 */
func tryExtractOrg(url string) string {
	res, err := http.Get(url)
	org := ""

	if err != nil {
		log.Fatal("Could not connect to URL provided. Quitting.")
	}

	if res.TLS != nil {
		// 0th element is always the last certificate in the chain, which is the one that
		// we want to examine.
		cert := res.TLS.PeerCertificates[0]
		orgs := cert.Subject.Organization

		if len(orgs) < 1 {
			log.Fatal("URL provided does not contain an organization. Quitting.")
		} else {
			// This may cause some bugs later on if there is more than 1 organization name
			// within the certificate
			org = orgs[0]
		}
	} else {
		log.Fatal("URL provided does not use TLS. Quitting.")
	}

	return org
}

/* printStatistics: prints statistics about which top level domains occur the most
 * frequently. Can be useful in helping to remove false positives, or gain insight
 * into subdomain distribution. Probably will add more useful stats later.
 */
func printStatistics(subdomains *map[string]int) {
	domains := make(map[string]int)

	for k := range *subdomains {
		d, err := publicsuffix.EffectiveTLDPlusOne(k)

		if err != nil {
			log.Warn("printStatistics: Failed to parse subdomain name")
		} else {
			if _, ok := domains[d]; ok {
				domains[d]++
			} else {
				domains[d] = 1
			}
		}
	}

	for domain, occurances := range domains {
		log.WithFields(log.Fields{
			"Occurances": occurances,
			"Domain":     domain,
		}).Info(" . . . ")
	}
}

/* ayy */
func printASCIIArt(major int, minor int) {
	art := `
  __________
  \\        | SAN CRAWLER v%d.%d: Uncle Rico's Time Machine
   \\       |    @cramppet
    \\@@@@@@|   
	`
	fmt.Printf(art+"\n", major, minor)
}

func main() {
	var print = flag.Bool("p", false, "")
	var keyword = flag.String("k", "", "")
	var org = flag.String("s", "", "")
	var outfile = flag.String("o", "", "")
	var autoURL = flag.String("u", "", "")
	var subdomains map[string]int

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "SANCrawler: reverses x509 metadata using CT logs\n\n")
		fmt.Fprintf(out, "Example: ./sancrawler -u https://example.com/ -o example.out\n\n")
		fmt.Fprintf(out, "Discovery modes:\n")
		fmt.Fprintf(out, "  -k  Keyword to match on.\n")
		fmt.Fprintf(out, "  -u  URL; attempt auto-extraction of x509 Subject's Organization field.\n")
		fmt.Fprintf(out, "Output:\n")
		fmt.Fprintf(out, "  -o  Use this output file.\n")
		fmt.Fprintf(out, "Auxiliary:\n")
		fmt.Fprintf(out, "  -p  Print domain statistics (ie. subdomain distribution) to stdout.\n")
	}

	start := time.Now()

	flag.Parse()
	printASCIIArt(2, 1)

	log.Info("SANCrawler running")

	// If we want to try the auto extraction, then we are implictly choosing to
	// use the organization mode.

	if *autoURL != "" {
		log.WithFields(log.Fields{
			"URL": *autoURL,
		}).Info("Attempting auto-extraction from URL")

		*org = tryExtractOrg(*autoURL)

		if *org != "" {
			log.WithFields(log.Fields{
				"Organization": *org,
			}).Info("Using extracted organization as seed")
		}
	}

	// Switch between the different possible modes, first one we see is the one
	// we end up doing. Passing multiple modes doesn't make a lot of sense, unless
	// we want to combine results or something.

	if *keyword != "" {
		subdomains = getDomainsByKeyword(*keyword)
	} else if *org != "" {
		subdomains = getDomainsByKeyword(*org)
	}

	// Why not show this bad motherfucker off?

	elapsed := time.Since(start)

	// Do we want to print the stats to standard out?

	if *print {
		log.Info("Printing domains statistics ...")
		printStatistics(&subdomains)
	}

	// Do we want to write to an output file?

	if *outfile != "" {
		log.WithFields(log.Fields{
			"Outfile": *outfile,
		}).Info("Writing results to output file")

		fHandle, err := os.Create(*outfile)

		if err != nil {
			panic(err)
		}

		bufWriter := bufio.NewWriter(fHandle)
		newLine := []byte("\n")
		defer fHandle.Close()

		for k := range subdomains {
			bufWriter.WriteString(k)
			bufWriter.Write(newLine)
		}

		bufWriter.Flush()
	}

	log.WithFields(log.Fields{
		"Runtime": elapsed,
	}).Info("SANCrawler shutting down")
}
