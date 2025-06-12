package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	certFile    = flag.String("cert", "", "Path to TLS certificate")
	keyFile     = flag.String("key", "", "Path to TLS key")
	clientCert  = flag.String("client-cert", "", "Path to client certificate for kubelet connection")
	clientKey   = flag.String("client-key", "", "Path to client key for kubelet connection")
	caFile      = flag.String("ca", "", "Path to CA certificate")
	listenAddr  = flag.String("listen", ":10442", "Address to listen on")
	kubeletURL  = flag.String("kubelet-url", "https://localhost:10443", "URL of the real kubelet")
	denylistStr = flag.String("denylist", "/pods/exec,/pods/portforward", "Comma-separated list of denied paths")
)

func main() {
	flag.Parse()

	denylist := strings.Split(*denylistStr, ",")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		for _, denied := range denylist {
			if strings.HasPrefix(r.URL.Path, denied) {
				http.Error(w, "Denied by MITM proxy policy", http.StatusForbidden)
				return
			}
		}

		forwardRequest(w, r)
	})

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS cert/key: %v", err)
	}

	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("Failed to read CA file: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("Failed to append CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      *listenAddr,
		TLSConfig: tlsConfig,
	}

	log.Printf("MITM proxy listening on %s", *listenAddr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func forwardRequest(w http.ResponseWriter, r *http.Request) {
	caCert, _ := os.ReadFile(*caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		http.Error(w, "Failed to load client certificate", http.StatusInternalServerError)
		return
	}

	u, _ := url.Parse(*kubeletURL)
	tlsConfig := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{cert},
		ServerName:   u.Hostname(),
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Copy request to new request
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	u.Path = r.URL.Path
	u.RawQuery = r.URL.RawQuery

	req, err := http.NewRequest(r.Method, u.String(), strings.NewReader(string(bodyBytes)))
	if err != nil {
		http.Error(w, "Failed to create forward request", http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Upstream request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
