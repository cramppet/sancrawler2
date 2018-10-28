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

func crawlerFn(commonNameRegex *regexp.Regexp, sanRegex *regexp.Regexp) {
	for {
		select {
		case <-doneChan:
			return

		case id := <-idChan:
			url := crtshBase + id
			res, err := http.Get(url)

			if err != nil {
				panic(err)
			}

			body, _ := ioutil.ReadAll(res.Body)
			bodys := string(body)
			commonNames := commonNameRegex.FindAllString(bodys, -1)
			san := sanRegex.FindAllString(bodys, -1)

			res.Body.Close()

			// Ignore the first common name since that is the common name of the issuer.
			if commonNames != nil {
				for i := 1; i < len(commonNames); i++ {
					// Remove commonName= and <
					nameChan <- commonNames[i][11 : len(commonNames[i])-1]
				}
			}

			if san != nil {
				for i := 0; i < len(san); i++ {
					// Remove DNS: and <
					nameChan <- san[i][4 : len(san[i])-1]
				}
			}
		}
	}
}

// The JSON coming back from crt.sh endpoints is not properly formatted. Thus,
// we have to make some changes to it in order for it to actually be parseable.
func patchJSON(jsondata []byte) string {
	var builder strings.Builder
	balanced := 0

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

func getNames(url string, httpParam string, numCrawlers int) map[string]int {
	certIDRegex, _ := regexp.Compile(`\?id\=\d+`)
	groupedCAIDs := []caID{}
	names := make(map[string]int)

	res, err := http.Get(url)

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)
	caJSON := patchJSON(body)

	if err := json.Unmarshal([]byte(caJSON), &groupedCAIDs); err != nil {
		fmt.Println("FATAL: Request timed out. Consider revising query.")
		return nil
	}

	for i := 0; i < len(groupedCAIDs); i++ {
		go (func(ca caID) {
			caURL := fmt.Sprintf("https://crt.sh/?icaid=%d&p=1&n=%d&%s", ca.ID, ca.NumCerts, httpParam)
			res, err := http.Get(caURL)

			if err != nil {
				panic(err)
			}

			caBody, _ := ioutil.ReadAll(res.Body)
			ids := certIDRegex.FindAllString(string(caBody), -1)

			defer res.Body.Close()

			for _, id := range ids {
				idChan <- id
			}

			doneChan <- true
		})(groupedCAIDs[i])
	}

	count := 0
	for count != len(groupedCAIDs) {
		select {
		case <-doneChan:
			count++
		default:
			continue
		}
	}

	fmt.Printf("Processing %d IDs with %d goroutines . . . ", len(idChan), numCrawlers)

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

func getDomainsByOrg(orgname string, numCrawlers int) map[string]int {
	orgname = url.PathEscape(orgname)
	url := crtshBase + crtshOrg + orgname
	httpParam := "O=" + orgname
	return getNames(url, httpParam, numCrawlers)
}

func getDomainsByKeyword(keyword string, numCrawlers int) map[string]int {
	keyword = url.PathEscape(keyword)
	url := crtshBase + crtshKeyword + keyword
	httpParam := "q=" + keyword
	return getNames(url, httpParam, numCrawlers)
}

func printASCIIArt() {
	art := `
  __________
  \\        | SAN CRAWLER v2: Electric Boogaloo
   \\       |    @cramppet
    \\@@@@@@|   
  `
	fmt.Println(art)
}

func main() {
	var keyword = flag.String("k", "", "Keyword to match on. Be careful with wildcard.")
	var org = flag.String("s", "", "Organization name to match on. Be careful with wildcard.")
	var print = flag.Bool("p", false, "Print results to stdout")
	var threads = flag.Int("t", 75, "Number of goroutines to use")
	var outfile = flag.String("o", "", "Output file")
	flag.Parse()

	idChan = make(chan string, maxChanLen)
	nameChan = make(chan string, maxChanLen)
	doneChan = make(chan bool, *threads)

	printASCIIArt()
	subdomains := make(map[string]int)
	start := time.Now()

	if *keyword != "" {
		subdomains = getDomainsByKeyword(*keyword, *threads)
	} else if *org != "" {
		subdomains = getDomainsByOrg(*org, *threads)
	}

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
