package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	crtshBase    = "https://crt.sh/"
	crtshOrg     = "?group=icaid&output=json&O="
	crtshKeyword = "?group=icaid&output=json&q="
	maxChanLen   = 100000
)

var nameChan chan string
var idChan chan string
var doneChan chan bool

type caID struct {
	ID       int `json:"issuer_ca_id"`
	NumCerts int `json:"num_certs"`
}

/* crawlerFn: Goroutine crawler function. Regexs can be shared safely between
 * goroutines as long as they aren't changing, which ours don't. So, we use 1
 * regex struct for each type we want to extract and pass pointers to it for
 * efficiency.
 */
func crawlerFn(commonNameRegex *regexp.Regexp, sanRegex *regexp.Regexp) {
	for {
		select {
		// Once this case becomes avaliable, it means that there are no more IDs
		// to process, so we can exit. Other goroutines may still be processing the
		// remaining IDs.
		case <-doneChan:
			return

		// New ID to process?
		case id := <-idChan:
			url := crtshBase + id
			res, err := http.Get(url)

			if err != nil {
				// BUG: crt.sh seems to be imposing some kind of undocumented rate-limiting. These
				// lines have solved the problem for me, experimentally.
				time.Sleep(5 * time.Second)
				res, err = http.Get(url)
				if err != nil {
					// Bail out if that doesn't work.
					panic(err)
				}
			}

			// We use regexs to extract what we want from the output of the decoded certificate.
			// The certificate is shown in a format originally derived from this RFC:
			// https://tools.ietf.org/html/rfc1422#appendix-A
			//
			// So, because we are processing an extended version of that spec which happens to
			// exist inside HTML, we can use regexs instead of a full HTML parser. This has
			// tremendous performance gains without any risk.
			body, _ := ioutil.ReadAll(res.Body)
			bodys := string(body)
			commonNames := commonNameRegex.FindAllString(bodys, -1)
			san := sanRegex.FindAllString(bodys, -1)

			res.Body.Close()

			// Ignore the first common name since that is the common name of the issuer.
			if commonNames != nil {
				for i := 1; i < len(commonNames); i++ {
					// Remove "commonName=" and "<"
					nameChan <- commonNames[i][11 : len(commonNames[i])-1]
				}
			}

			if san != nil {
				for i := 0; i < len(san); i++ {
					// Remove "DNS:" and "<"
					nameChan <- san[i][4 : len(san[i])-1]
				}
			}
		}
	}
}

/* patchJSON: The JSON coming back from the crt.sh is not properly formatted. Thus,
 * we have to make some changes to it in order for it to actually be parseable all
 * in one go.
 */
func patchJSON(jsondata []byte) string {
	var builder strings.Builder
	balanced := 0

	// All we really do here is add commas between the individual records that
	// crt.sh returned to us. Idk if there is a better way, but this seems to
	// be fast enough.

	builder.Grow(len(jsondata))
	builder.WriteByte('[')

	for i := 0; i < len(jsondata); i++ {
		builder.WriteByte(jsondata[i])
		if jsondata[i] == '{' {
			balanced++
		} else if jsondata[i] == '}' {
			balanced--
		}
		if balanced == 0 && i != len(jsondata)-1 {
			builder.WriteByte(',')
		}
	}

	builder.WriteByte(']')
	return builder.String()
}

/* getNames: Gets the names, ie. domain/subdomain names from certificates that are
 * returned from searching crt.sh for certificates matching a certain search URL
 * with a certain HTTP GET parameter
 *
 * Higher-level functions (see below) use this by passing a url that corresponds to
 * the specific endpoint we retrieve our search query results from. Since the output
 * format is always the same, we can use this function to parse the names, no matter
 * what the actual search type is. This makes it easy to add additional features
 * later, if desired.
 */
func getNames(url string, httpParam string, numCrawlers int) map[string]int {
	certIDRegex, _ := regexp.Compile(`\?id\=\d+`)
	groupedCAIDs := []caID{}
	names := make(map[string]int)

	res, err := http.Get(url)

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	// Lemme patch that JSON real quick

	body, _ := ioutil.ReadAll(res.Body)
	caJSON := patchJSON(body)

	if err := json.Unmarshal([]byte(caJSON), &groupedCAIDs); err != nil {
		fmt.Println("FATAL: Request timed out. Consider revising query.")
		return nil
	}

	// We grouped by CAID because this results in better performance overall. Crt.sh will
	// aggregate results into a table grouped by their CAID rather than return all matching
	// results. This is basically to prevent large organizations from timing out.

	for i := 0; i < len(groupedCAIDs); i++ {
		// Hey man, its go, and when its go, you let it do what go does. CONCURRENCY.
		go (func(ca caID) {
			// Each CA may have issued several hundreds certs, so in the future, we may have to
			// actually paginate these results. Right now, we do a performance hack and try to get
			// all the results in one go. So we tell it to return 1 page with all the issued certs.
			caURL := fmt.Sprintf("https://crt.sh/?icaid=%d&p=1&n=%d&%s", ca.ID, ca.NumCerts, httpParam)
			res, err := http.Get(caURL)

			// Bail out if shit goes south
			if err != nil {
				panic(err)
			}

			// I don't feel guilty about this one either. Performance feels too good man. Also, we
			// never ACTUALLY parse the HTML, we just look for patterns of text that correspond to IDs,
			// and this text happens to be inside HTML. Unless the site changes dramatically, I think
			// its gonna be fine.
			caBody, _ := ioutil.ReadAll(res.Body)
			ids := certIDRegex.FindAllString(string(caBody), -1)

			defer res.Body.Close()

			for _, id := range ids {
				idChan <- id
			}

			doneChan <- true
		})(groupedCAIDs[i])
	}

	// Concurrency is fun

	count := 0
	for count != len(groupedCAIDs) {
		select {
		case <-doneChan:
			count++
		default:
			continue
		}
	}

	fmt.Printf("\nProcessing %d IDs with %d goroutines . . . ", len(idChan), numCrawlers)

	// At this point, we have a bunch of IDs corresponding to different endpoints on crt.sh
	// which we are going to process and extract names from. These IDs came from the search
	// query we just performed, optimized by grouping by CAID to try to prevent the result
	// from timing out. But what we got from the step above was just the IDs, not the actual
	// entires. Some of these IDs are duplicates in terms of names, but there is no way
	// to filter across that as far as I know in crt.sh

	// Our single regex structs shared with all goroutines

	commonNameRegex := regexp.MustCompile(`(?i)commonName=.*?<`)
	sanRegex := regexp.MustCompile(`(?i)DNS:.*?<`)

	// Spawn the crawlers

	for i := 0; i < numCrawlers; i++ {
		go crawlerFn(commonNameRegex, sanRegex)
	}

	// Let the IDs drain from the channel
	// Keep track of the names coming from the other channel

	for len(idChan) > 0 {
		select {
		case n := <-nameChan:
			names[n] = 0
		default:
			continue
		}
	}

	// Let crawlers begin to terminate

	for i := 0; i < numCrawlers; i++ {
		doneChan <- true
	}

	// Wait for all crawlers to terminate and the name channel to drain

	for len(nameChan) > 0 || len(doneChan) > 0 {
		select {
		case n := <-nameChan:
			names[n] = 0
		default:
			continue
		}
	}

	fmt.Printf("got %d unique subdomains\n\n", len(names))
	return names
}

/* getDomainsByOrg: Get all the names belonging to a certain organization name.
 * Also use a specified number of "crawlers" which are goroutines.
 */
func getDomainsByOrg(orgname string, numCrawlers int) map[string]int {
	orgname = url.QueryEscape(orgname)
	url := crtshBase + crtshOrg + orgname
	httpParam := "O=" + orgname
	return getNames(url, httpParam, numCrawlers)
}

/* getDomainsByKeyword: General search, any match on any fields in x509 spec.
 */
func getDomainsByKeyword(keyword string, numCrawlers int) map[string]int {
	keyword = url.QueryEscape(keyword)
	url := crtshBase + crtshKeyword + keyword
	httpParam := "q=" + keyword
	return getNames(url, httpParam, numCrawlers)
}

/* ayy */
func printASCIIArt(major int, minor int) {
	art := `
  __________
  \\        | SAN CRAWLER v%d.%d: Uncle Rico's Time Machine
   \\       |    @cramppet
    \\@@@@@@|   
  `
	fmt.Printf(art, major, minor)
}

func main() {
	var keyword = flag.String("k", "", "Keyword to match on. Be careful with wildcard.")
	var org = flag.String("s", "", "Organization name to match on. Be careful with wildcard.")
	var print = flag.Bool("p", false, "Print results to stdout")
	var threads = flag.Int("t", 50, "Number of goroutines to use")
	var outfile = flag.String("o", "", "Output file")
	flag.Parse()

	idChan = make(chan string, maxChanLen)
	nameChan = make(chan string, maxChanLen)
	doneChan = make(chan bool, *threads)

	printASCIIArt(2, 1)
	subdomains := make(map[string]int)
	start := time.Now()

	if *keyword != "" {
		subdomains = getDomainsByKeyword(*keyword, *threads)
	} else if *org != "" {
		subdomains = getDomainsByOrg(*org, *threads)
	}

	// Why not show this bad motherfucker off?
	elapsed := time.Since(start)

	if *print {
		for k := range subdomains {
			fmt.Println(k)
		}
	}

	if *outfile != "" {
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

	fmt.Printf("\nSAN Crawler took %v\n\n", elapsed)
}
