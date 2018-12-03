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
- Then, just do `go build sancrawler.go` from the sancrawler2 directory

## How to use

**Keep in mind that the heuristic which SANCrawler uses in practice can sometimes**
**lead to incorrect or inaccurate results. Results not guaranteed.**

You need to acquire some kind of metadata from the certificates of your target.
Sometimes this is very simple, other times nothing exists at all. The best way
I have found is simply navigating to the homepage of the target and checking if
there is an "Organization" or "Organizational Unit" field present in the (presumed)
X509 certificate, and if so, to use that. Otherwise you'll have to get creative 
to find something useable. 

SANCrawler implements two different modes, a **keyword search mode** and a strict 
**organization search mode**. Use whichever you prefer, the keyword search is a more
general search which encompasses all that the organization search mode does, so
if the query works in the organization mode, it will work just as well or perhaps
better in the keyword mode. 

The purpose of the organization mode given what I just said is to try to refine
the results more to remove some false positives. 

### Wildcard

You can use the `%` character as a wildcard in either of the search modes. This is
incidential due to the crt.sh service providing this feature. Be careful when using
this as searches of the form `%QUERY%` tend not to work. 

## Examples

1. Using the organization search mode on Apple. **Enumerating 16,000 subdomains in under a minute.** 

```
./sancrawler -s "Apple Inc." -o apple.out

  __________
  \\        | SAN CRAWLER v2: Electric Boogaloo
   \\       |    @cramppet
    \\@@@@@@|

Processing 12104 IDs with 75 goroutines . . . got 16221 unique subdomains


SAN Crawler took 54.443376278s
```

2. Using the keyword search mode with a seed value taken from nsa.gov's X509 cert.

```
./sancrawler -k "National Security Agency%" -p

  __________
  \\        | SAN CRAWLER v2: Electric Boogaloo
   \\       |    @cramppet
    \\@@@@@@|

Processing 27 IDs with 75 goroutines . . . got 12 unique subdomains

www2.nsa.gov
www.nsa.gov
nsa.gov
m.intelligencecareers.gov
www.intelligencecareers.gov
apps.nsa.gov
apps-test.nsa.gov
m.nsa.gov
vpn.nsa.gov
stage.nsa.gov
captcha.nsa.gov
intelligencecareers.gov

SAN Crawler took 295.046208ms
```
