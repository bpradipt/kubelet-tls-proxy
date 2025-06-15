package test

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	certFile  = flag.String("cert", "", "Path to client TLS cert")
	keyFile   = flag.String("key", "", "Path to client TLS key")
	caFile    = flag.String("ca", "", "Path to CA certificate")
	targetURL = flag.String("url", "https://localhost:10442", "Target URL of Kubelet TLS proxy")
)

func makeRequest(method, path, body string) {
	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("Failed to read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load client cert/key: %v", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{cert},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	url := *targetURL + path
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("%s %s => %d", method, path, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response: %s\n", string(respBody))
}

func main() {
	flag.Parse()

	tests := []struct {
		method string
		path   string
		body   string
		desc   string
	}{
		{"GET", "/pods", "", "Allowed GET request"},
		{"GET", "/pods/exec", "", "Denied GET request to /pods/exec"},
		{"POST", "/logs", "log-data", "Allowed POST request"},
		{"POST", "/pods/portforward", "", "Denied POST request to /pods/portforward"},
	}

	for _, t := range tests {
		log.Printf("Test: %s", t.desc)
		makeRequest(t.method, t.path, t.body)
	}
}
