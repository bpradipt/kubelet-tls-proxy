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
	certFile    = flag.String("cert", "", "TLS cert to terminate kube-apiserver connection")
	keyFile     = flag.String("key", "", "TLS key to terminate kube-apiserver connection")
	clientCert  = flag.String("client-cert", "", "Client cert to talk to kubelet")
	clientKey   = flag.String("client-key", "", "Client key to talk to kubelet")
	caFile      = flag.String("ca", "", "CA cert to trust kubelet")
	listenAddr  = flag.String("listen", "<IP-address>:10250", "MITM proxy listen address (e.g., 172.18.0.3:10250)")
	kubeletURL  = flag.String("kubelet-url", "https://localhost:10250", "Upstream kubelet URL")
	kubeletHost = flag.String("kubelet-host", "", "ServerName override for kubelet TLS verification (e.g. peer-pods-worker)")
	denylistStr = flag.String("denylist", "/pods/exec,/pods/portforward", "Comma-separated list of kubelet API paths to deny")
	insecure    = flag.Bool("insecure", false, "Allow insecure connections to kubelet (self-signed certs) - use with caution!")
	useRego     = flag.Bool("rego", false, "Enable Rego policy evaluation instead of simple denylist")
	regoPath    = flag.String("rego-path", "policy.rego", "Path to Rego policy file")
)

func main() {
	flag.Parse()

	denylist := strings.Split(*denylistStr, ",")
	log.Printf("MITM proxy starting up...")
	log.Printf("Listening on: %s", *listenAddr)
	log.Printf("Forwarding to kubelet at: %s", *kubeletURL)
	if *useRego {
		// regoPath must be provided if useRego is true
		if *regoPath == "" {
			log.Fatal("Rego mode enabled but no rego-path provided. Please specify a path to the Rego policy file.")
		}
		log.Printf("Rego mode enabled. Loading policy from: %s", *regoPath)
	} else {
		log.Printf("Denylist paths: %v", denylist)
	}

	log.Println("Loading terminating TLS cert for kube-apiserver connections...")
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Error loading proxy cert/key: %v", err)
	}

	log.Println("Reading CA certificate for incoming client verification...")
	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("Error reading CA file: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("Failed to append CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[REQ] %s %s", r.Method, r.URL.Path)
		if *useRego {
			denied, err := evaluatePolicy(*regoPath, r.Method, r.URL.Path)
			if err != nil {
				log.Printf("[POLICY ERROR] %v", err)
				http.Error(w, "Policy evaluation failed", http.StatusInternalServerError)
				return
			}
			if denied {
				log.Printf("[DENY] Blocked path: %s", r.URL.Path)
				http.Error(w, "Denied by policy", http.StatusForbidden)
				return
			}
		} else {
			for _, denied := range denylist {
				if strings.HasPrefix(r.URL.Path, denied) {
					log.Printf("[DENY] Blocked path: %s", r.URL.Path)
					http.Error(w, "Denied by policy", http.StatusForbidden)
					return
				}
			}
		}

		// Websocket or SPDY upgrade handling for exec, attach
		if isUpgradeRequest(r) {
			log.Printf("[WS] Detected connection upgrade request for %s", r.URL.Path)
			handleStreamTunnel(w, r)
			return
		}

		forwardRequest(w, r)
	})

	server := &http.Server{
		Addr:      *listenAddr,
		TLSConfig: tlsConfig,
	}
	log.Printf("Starting MITM proxy server on %s", *listenAddr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func forwardRequest(w http.ResponseWriter, r *http.Request) {
	log.Println("Preparing to forward request to kubelet...")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	log.Println("Loading client certificate for upstream connection to kubelet...")
	clientCerts, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		log.Printf("Client cert error: %v", err)
		http.Error(w, "Failed to load client cert/key", http.StatusInternalServerError)
		return
	}

	log.Println("Reading CA cert for kubelet server validation...")
	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Printf("Error reading CA cert: %v", err)
		http.Error(w, "Failed to read CA cert", http.StatusInternalServerError)
		return
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	upstreamURL, err := url.Parse(*kubeletURL)
	if err != nil {
		log.Printf("Invalid kubelet URL: %v", err)
		http.Error(w, "Invalid kubelet URL", http.StatusInternalServerError)
		return
	}
	serverName := *kubeletHost
	if serverName == "" {
		serverName = upstreamURL.Hostname()
	}
	log.Printf("Connecting to kubelet with ServerName override: %s", serverName)

	clientTLS := &tls.Config{
		RootCAs:            caPool,
		Certificates:       []tls.Certificate{clientCerts},
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: *insecure, // Allow self-signed certs for kubelet
	}

	transport := &http.Transport{TLSClientConfig: clientTLS}
	client := &http.Client{Transport: transport}

	upstreamURL.Path = r.URL.Path
	upstreamURL.RawQuery = r.URL.RawQuery
	log.Printf("Forwarding request to: %s", upstreamURL.String())

	req, err := http.NewRequest(r.Method, upstreamURL.String(), strings.NewReader(string(body)))
	if err != nil {
		log.Printf("Failed to create upstream request: %v", err)
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Upstream kubelet error: %v", err)
		http.Error(w, fmt.Sprintf("Upstream kubelet error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	log.Printf("Received response from kubelet: %s", resp.Status)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func isUpgradeRequest(r *http.Request) bool {

	log.Printf("[DEBUG] Connection header: %q, Upgrade header: %q", r.Header.Get("Connection"), r.Header.Get("Upgrade"))

	connectionHeader := strings.ToLower(r.Header.Get("Connection"))
	upgradeHeader := strings.ToLower(r.Header.Get("Upgrade"))

	// connectionHeader might be: "Upgrade, X-Stream-Protocol-Version"
	for _, h := range strings.Split(connectionHeader, ",") {
		if strings.TrimSpace(h) == "upgrade" && upgradeHeader != "" {
			return true
		}
	}
	return false
}

func handleStreamTunnel(w http.ResponseWriter, r *http.Request) {
	log.Printf("[TUNNEL] Initiating upgraded stream: %s %s", r.Method, r.URL.Path)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBufRW, err := hj.Hijack()
	if err != nil {
		log.Printf("[TUNNEL ERROR] Client hijack failed: %v", err)
		return
	}
	defer clientConn.Close()

	// Load kubelet TLS config
	clientCerts, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		log.Printf("[TUNNEL ERROR] Load client cert: %v", err)
		return
	}
	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Printf("[TUNNEL ERROR] Load CA: %v", err)
		return
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	upstreamURL, _ := url.Parse(*kubeletURL)
	addr := upstreamURL.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	serverName := *kubeletHost
	if serverName == "" {
		serverName = upstreamURL.Hostname()
	}

	kubeletConn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:            caPool,
		Certificates:       []tls.Certificate{clientCerts},
		ServerName:         serverName,
		InsecureSkipVerify: *insecure,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		log.Printf("[TUNNEL ERROR] TLS to kubelet failed: %v", err)
		return
	}
	defer kubeletConn.Close()

	// Forward the upgrade request to kubelet
	if err := r.Write(kubeletConn); err != nil {
		log.Printf("[TUNNEL ERROR] Write to kubelet failed: %v", err)
		return
	}

	// Stream data in both directions
	log.Println("[TUNNEL] Bi-directional stream started")
	done := make(chan struct{}, 2)

	go func() {
		_, err := io.Copy(kubeletConn, clientBufRW)
		if err != nil {
			log.Printf("[TUNNEL ERROR] client → kubelet: %v", err)
		}
		kubeletConn.CloseWrite()
		done <- struct{}{}
	}()

	go func() {
		_, err := io.Copy(clientConn, kubeletConn)
		if err != nil {
			log.Printf("[TUNNEL ERROR] kubelet → client: %v", err)
		}
		clientConn.Close()
		done <- struct{}{}
	}()

	<-done
	log.Println("[TUNNEL] Stream closed")
}
