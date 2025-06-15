package kubelet

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	certFile := flag.String("cert", "tls.crt", "Path to TLS certificate file")
	keyFile := flag.String("key", "tls.key", "Path to TLS key file")
	caFile := flag.String("ca", "ca.crt", "Path to CA certificate for verifying clients")
	listenAddr := flag.String("listen", ":10443", "Address to listen on")
	flag.Parse()

	// Load server certificate
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load server cert: %v", err)
	}

	// Load and set client CA
	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock kubelet received: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fmt.Sprintf("Mock kubelet response to %s %s\n", r.Method, r.URL.Path))
	})

	srv := &http.Server{
		Addr:      *listenAddr,
		TLSConfig: tlsConfig,
	}

	log.Printf("Mock kubelet listening on https://%s", *listenAddr)
	err = srv.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("ListenAndServeTLS: %v", err)
	}
}
