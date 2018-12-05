all:
	go get github.com/lib/pq
	go get github.com/sirupsen/logrus
	go get golang.org/x/net/publicsuffix
	go build sancrawler.go

clean:
	rm sancrawler
