package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/http2"

	tls "github.com/hellais/utls-light/tls"
)

func getRequest(conn net.Conn, requestHostname string, alpn string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Host: requestHostname, Scheme: "https"},
		Header: make(http.Header),
		Host:   requestHostname,
	}

	switch alpn {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0

		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	case "http/1.1", "":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(conn)
		if err != nil {
			return nil, err
		}
		return http.ReadResponse(bufio.NewReader(conn), req)
	default:
		return nil, fmt.Errorf("unsupported ALPN: %v", alpn)
	}
}

func logStatus(status string, serverName string, addr string) {
	f, err := os.OpenFile("domain-status.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	logline := fmt.Sprintf("%s,%s,%s\n", status, serverName, addr)
	fmt.Print(logline)
	if _, err = f.WriteString(logline); err != nil {
		panic(err)
	}
}

func testURL(serverName string) error {
	ips, err := net.LookupIP(serverName)
	if len(ips) == 0 || err != nil {
		logStatus("FAIL-DNS", serverName, "")
		return errors.New("failed to lookup IP")
	}
	addr := fmt.Sprintf("%s:443", ips[0].String())
	config := tls.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}}
	dialConn, err := net.DialTimeout("tcp", addr, time.Duration(2)*time.Second)
	if err != nil {
		logStatus("FAIL-CONNECT", serverName, addr)
		return err
	}
	tlsConn := tls.Client(dialConn, &config)
	tlsConn.Handshake()
	defer tlsConn.Close()
	_, err = getRequest(tlsConn, serverName, tlsConn.ConnectionState().NegotiatedProtocol)
	if err != nil {
		logStatus("FAIL-GET", serverName, addr)
		return err
	}
	logStatus("OK", serverName, addr)
	return nil
}

func main() {
	file, err := os.Open("tests/citizenlab-domains.txt")
	if err != nil {
		log.Fatal("Cannot open file")
	}
	defer file.Close()

	testDomains := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		testDomains = append(testDomains, domain)
	}

	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(testDomains), func(i, j int) { testDomains[i], testDomains[j] = testDomains[j], testDomains[i] })

	for idx := range testDomains {
		domain := testDomains[idx]
		err := testURL(domain)
		if err != nil {
			log.Printf("Failed to check %s %v", domain, err)
		}
	}

}
