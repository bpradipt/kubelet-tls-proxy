# Binary names
PROXY_BIN := tls_proxy
KUBELET_BIN := mock_kubelet
CLIENT_BIN := test_client

# Directories
TEST_DIR := test
CERT_DIR := certs

# Default target
.PHONY: all
all: build

.PHONY: build
build:
	go build -o $(PROXY_BIN) main.go rego_evaluate.go
	go build -o $(KUBELET_BIN) $(TEST_DIR)/kubelet/mock_kubelet.go
	go build -o $(CLIENT_BIN) $(TEST_DIR)/client/test_client.go

.PHONY: certs
certs:
	./generate_certs.sh $(CERT_DIR)

.PHONY: run-proxy
run-proxy:
	./$(PROXY_BIN) \
		--cert $(CERT_DIR)/tls.crt \
		--key $(CERT_DIR)/tls.key \
		--client-cert $(CERT_DIR)/client.crt \
		--client-key $(CERT_DIR)/client.key \
		--ca $(CERT_DIR)/ca.crt \
		--listen :10442 \
		--kubelet-url https://localhost:10443 & echo $$! > proxy.pid

.PHONY: run-mock
run-mock:
	./$(KUBELET_BIN) \
		--cert $(CERT_DIR)/tls.crt \
		--key $(CERT_DIR)/tls.key \
		--ca $(CERT_DIR)/ca.crt \
		--listen :10443 & echo $$! > kubelet.pid

.PHONY: test-client
test-client:
	./$(CLIENT_BIN) --ca $(CERT_DIR)/ca.crt --cert $(CERT_DIR)/client.crt --key $(CERT_DIR)/client.key

.PHONY: run_test
run_test: certs build run-mock run-proxy
	sleep 2
	$(MAKE) test-client
	$(MAKE) cleanup

.PHONY: cleanup
cleanup:
	-@kill `cat proxy.pid` 2>/dev/null || true
	-@kill `cat kubelet.pid` 2>/dev/null || true
	-@rm -f proxy.pid kubelet.pid
	-@rm -f $(PROXY_BIN) $(KUBELET_BIN) $(CLIENT_BIN)
	-@rm -rf $(CERT_DIR)/*
