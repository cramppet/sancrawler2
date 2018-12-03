package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

func getNames(orgname string) map[string]int {
	queryStr := `SELECT ci.ISSUER_CA_ID, ci.NAME_VALUE NAME_VALUE, 
	x509_altNames(c.CERTIFICATE, 2, TRUE) SAN_NAME, 
	x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) 
	COMMON_NAME FROM ca, ct_log_entry ctle, certificate_identity ci, 
	certificate c WHERE ci.ISSUER_CA_ID = ca.ID AND c.ID = ctle.CERTIFICATE_ID 
	AND ci.CERTIFICATE_ID = c.ID AND ((lower(ci.NAME_VALUE) LIKE lower('%s') 
	AND ci.NAME_TYPE = 'organizationName')) GROUP BY ci.ISSUER_CA_ID, 
	c.ID, NAME_VALUE, COMMON_NAME, SAN_NAME;`

	queryStr = fmt.Sprintf(queryStr, orgname)
	queryStr = strings.Replace(queryStr, "\n", " ", -1)

	connStr := "host=crt.sh user=guest dbname=certwatch"
	db, err := sql.Open("postgres", connStr)
	ret := make(map[string]int)

	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query(queryStr)

	if err != nil {
		log.Fatal(err)
	}

	for rows.Next() {
		var (
			caID   int64
			org    string
			common string
			san    string
		)

		if err := rows.Scan(&caID, &org, &common, &san); err != nil {
			log.Fatal(err)
		}

		ret[common] = 0
		ret[san] = 0
	}

	return ret
}

/* getDomainsByOrg: Get all the names belonging to a certain organization name.
 */
func getDomainsByOrg(orgname string) map[string]int {
	return getNames(orgname)
}

/* getDomainsByKeyword: General search, any match on any fields in x509 spec.
 */
func getDomainsByKeyword(keyword string) map[string]int {
	return getNames(keyword)
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
 * into subdomain distribution.
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
	var keyword = flag.String("k", "", "Keyword to match on. Be careful with wildcard.")
	var org = flag.String("s", "", "Organization name to match on. Be careful with wildcard.")
	var print = flag.Bool("p", false, "Print subdomain statistics to stdout")
	var outfile = flag.String("o", "", "Output file")
	var autoUrl = flag.String("u", "", "Attempt auto-extraction of organization from URL")
	flag.Parse()

	printASCIIArt(2, 1)
	subdomains := make(map[string]int)
	start := time.Now()

	log.Info("SANCrawler running")

	// If we want to try the auto extraction, then we are implictly choosing to
	// use the organization mode.

	if *autoUrl != "" {
		log.WithFields(log.Fields{
			"URL": *autoUrl,
		}).Info("Attempting auto-extraction from URL")

		*org = tryExtractOrg(*autoUrl)

		if *org != "" {
			log.WithFields(log.Fields{
				"Organization": *org,
			}).Info("Using extracted organization as seed")
		}
	}

	// Switch between the different possible modes, first one we see is the one
	// we end up doing. Passing multiple modes doesn't make a lot of sense, unless
	// we want to combine results later on.

	if *keyword != "" {
		subdomains = getDomainsByKeyword(*keyword)
	} else if *org != "" {
		subdomains = getDomainsByOrg(*org)
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
