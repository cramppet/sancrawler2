# SANCrawler2: Uncle Rico's Time Machine

SANCrawler is a tool designed to quickly extract information from the certificate
transparency aggregator [crt.sh](https://crt.sh/). 

Many companies unnecessarily place extra metadata in the X509 certificates used to 
implement TLS on external services. This metadata can be used to perform reverse
searches and uncover linked top level domains and subdomains which share the same
metadata. 

In much the same way that reverse WHOIS and DNS techniques allow penetration 
testers to enumerate external services, SANCrawler implements what can be thought 
of as "reverse X509" for the same purpose.

## How to build

- First, [install golang](https://golang.org/doc/install) 
- Then, just do a `make` from the sancrawler2 directory

## How to use

**Keep in mind that the heuristic which SANCrawler uses in practice can sometimes**
**lead to incorrect or inaccurate results. Results not guaranteed.**

SANCrawler now implements a mode to try and find sufficient metadata for you. You can 
specify the **url mode** with the `-u https://url.com` option and SANCrawler will do 
its best to detect the metadata if it exists. If that doesn't work you'll have to get 
creative to find something useable. 

SANCrawler implements one other mode to facilitate that, a **keyword search mode** 
that allows you to search by an arbitrary string it encompasses all that the same search 
fields that the URL search mode does. 

## Command Line Options

```
Discovery modes:
  -k  Keyword to match on.
  -u  URL; attempt auto-extraction of x509 Subject's Organization field.

Output:
  -o  Use this output file.

Auxiliary:
  -p  Print domain statistics (ie. subdomain distribution) to stdout.
```

## Examples

1. Using the URL mode on Apple. **Enumerating 16,576 subdomains in 48 seconds**

```
./sancrawler -u https://apple.com -o apple.out

  __________
  \\        | SAN CRAWLER v2.1: Uncle Rico's Time Machine
   \\       |    @cramppet
    \\@@@@@@|   
	
INFO[0000] SANCrawler running                           
INFO[0000] Attempting auto-extraction from URL           URL="https://apple.com"
INFO[0000] Using extracted organization as seed          Organization="Apple Inc."
INFO[0048] Writing results to output file                Outfile=apple.out
INFO[0048] SANCrawler shutting down                      Runtime=48.736586958s
```

2. Using the keyword search mode with a seed value taken from whitehouse.gov's cert.

```
⇒  ./sancrawler -k "Executive Office of the President - Office of Administration" -p

  __________
  \\        | SAN CRAWLER v2.1: Uncle Rico's Time Machine
   \\       |    @cramppet
    \\@@@@@@|   
	
INFO[0000] SANCrawler running                           
INFO[0001] Printing domains statistics ...              
INFO[0001]  . . .                                        Domain=ai.gov Occurances=2
INFO[0001]  . . .                                        Domain=bebest.gov Occurances=2
INFO[0001]  . . .                                        Domain=ostp.gov Occurances=4
INFO[0001]  . . .                                        Domain=crisisnextdoor.gov Occurances=2
INFO[0001]  . . .                                        Domain=ondcp.gov Occurances=2
INFO[0001]  . . .                                        Domain=whitehousedrugpolicy.gov Occurances=2
INFO[0001]  . . .                                        Domain=budget.gov Occurances=2
INFO[0001]  . . .                                        Domain=whitehouse.gov Occurances=7
INFO[0001]  . . .                                        Domain=eop.gov Occurances=2
INFO[0001]  . . .                                        Domain=wh.gov Occurances=5
INFO[0001]  . . .                                        Domain=omb.gov Occurances=2
INFO[0001]  . . .                                        Domain=greatagain.gov Occurances=2
INFO[0001] SANCrawler shutting down                      Runtime=1.755120376s
```
