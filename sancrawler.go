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
	"strings"
	"time"

	// Lets hope this one works better than psycopg2
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

/* getNames: Retrieves the common names and subject alternative names (SANs)
 * from the postgres instance run by crt.sh, you can find details about their
 * complicated database schema here: https://github.com/crtsh/certwatch_db
 */
func getNames(queryStr string, param string) map[string]int {
	queryStr = fmt.Sprintf(queryStr, param)
	queryStr = strings.Replace(queryStr, "\n", " ", -1)

	// https://groups.google.com/forum/#!msg/crtsh/sUmV0mBz8bQ/K-6Vymd_AAAJ
	connStr := "host=crt.sh user=guest dbname=certwatch"
	db, err := sql.Open("postgres", connStr)
	names := make(map[string]int)

	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query(queryStr)

	if err != nil {
		log.Fatal(err)
	}

	// Scan through the records returned and keep track of the information we
	// actually care about.
	for rows.Next() {
		var (
			common string
			san    string
		)

		// Note: Some of these results may not be actual domains, recall these are
		// just common names and SANs. They only have to be resolvable/accessible for
		// whatever system is using them. This means you may find internal domain names
		// as SANs that aren't fully qualified. You are very likely to encounter wildcard
		// entires too.

		if err := rows.Scan(&common, &san); err != nil {
			log.Fatal(err)
		}

		// Make sure to lowercase to avoid duplicates based on mixed cases

		common = strings.ToLower(common)
		san = strings.ToLower(san)

		// Check if they are already in our map, this lookup is O(1).

		if _, ok := names[common]; ok {
			continue
		}

		if _, ok := names[san]; ok {
			continue
		}

		names[common] = 0
		names[san] = 0
	}

	return names
}

/* getDomainsByOrg: Get all the names belonging to a certain organization.
 */
func getDomainsByOrg(orgname string) map[string]int {
	// I have never liked SQL and this query is probably shit, but it returns
	// results faster than any of the others I tried and I have no idea why.
	queryStr := `SELECT x509_altNames(c.CERTIFICATE, 2, TRUE) SAN_NAME, 
	x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) COMMON_NAME 
	FROM ca, ct_log_entry ctle, certificate_identity ci, certificate c 
	WHERE ci.ISSUER_CA_ID = ca.ID AND c.ID = ctle.CERTIFICATE_ID 
	AND ci.CERTIFICATE_ID = c.ID AND ((lower(ci.NAME_VALUE) LIKE lower('%s') 
	AND ci.NAME_TYPE = 'organizationName')) GROUP BY ci.ISSUER_CA_ID, 
	c.ID, NAME_VALUE, COMMON_NAME, SAN_NAME;`
	return getNames(queryStr, orgname)
}

/* getDomainsByKeyword: General search, any match on any fields in x509 spec.
 */
func getDomainsByKeyword(keyword string) map[string]int {
	queryStr := `SELECT x509_altNames(c.CERTIFICATE, 2, TRUE) SAN_NAME, 
	x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) COMMON_NAME 
	FROM ca, ct_log_entry ctle, certificate_identity ci, certificate c 
	WHERE ci.ISSUER_CA_ID = ca.ID AND c.ID = ctle.CERTIFICATE_ID 
	AND ci.CERTIFICATE_ID = c.ID AND lower(ci.NAME_VALUE) LIKE lower('%s')
	GROUP BY ci.ISSUER_CA_ID, c.ID, NAME_VALUE, COMMON_NAME, SAN_NAME;`
	return getNames(queryStr, keyword)
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

	// https://stackoverflow.com/questions/23725924/can-gos-flag-package-print-usage
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "SANCrawler: reverses x509 metadata using CT logs\n")
		fmt.Fprintf(out, "Examples: ./sancrawler -u https://example.com/ -o example.out\n")
		fmt.Fprintf(out, "          ./sancrawler -s \"Company name\" -o example.out -p\n\n")
		fmt.Fprintf(out, "Discovery modes:\n")
		fmt.Fprintf(out, "  -k  Keyword to match on. Be careful with wildcard.\n")
		fmt.Fprintf(out, "  -s  Organization name to match on. Be careful with wildcard.\n")
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
