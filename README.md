# Introduction

This is an experimental project introducing policy based validation for Kubelet APIs.
The motivation for this approach is to explore the possibility of creating confidential Kubernetes worker nodes
where the control plane is untrusted.

The policy based validation is inspired from [Kata agent](https://github.com/kata-containers/kata-containers/blob/main/docs/how-to/how-to-use-the-kata-agent-policy.md).

## Build

```sh
make build
```

## Running

In order to use the TLS proxy you must ensure the following:

- The `kubelet` must be running on `localhost`. IOW, the `address` field in the `kubelet` [configuration](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/#create-the-config-file) must be `localhost`.
- The TLS proxy must be running on the public interface for kube-api-server to connect to.
- Use the same `kubelet` port for the TLS proxy as configured in the `kubelet` configuration (default port: 10250).

## Trying out in a Kind cluster

### Create cluster

```sh
kind create cluster --config kind-config.yaml --kubeconfig tls.kubeconfig
```

### Create certs

- Login to the control plane node.
  
```sh
docker exec -it tls-control-plane bash
```

The following commands are executed within the control plane node

- Get organisation name from the apiserver kubelet client cert

```sh
export CERT="/etc/kubernetes/pki/apiserver-kubelet-client.crt"
ORG_NAME=$(openssl x509 -noout -subject -in $CERT -nameopt multiline | sed -n 's/ *organizationName *= //p')
echo $ORG_NAME
```

- Create cert for the TLS proxy

```sh
SUBJECT="/O=$ORG_NAME/CN=tls-proxy-client"
openssl req -subj $SUBJECT -new -newkey rsa:2048 -nodes -out  tls.csr -keyout tls.key
openssl x509 -req -in  tls.csr  -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out tls.crt -days 375 -sha256
```

- Exit from the control plane node

- Copy the `tls.crt` and `tls.key` from the control plane node

```sh
docker cp tls-control-plane:/tls.crt .
docker cp tls-control-plane:/tls.key .
```

### Running the TLS proxy

- Copy the `tls.crt` and `tls.key` to the worker node

```sh
docker cp tls.crt tls-worker:/
docker cp tls.key tls-worker:/
```

- Copy the proxy and rego policy file to the worker node

```sh
docker cp tls_proxy tls-worker:/
docker cp rego/policy.rego tls-worker:/
```

### Running the proxy

- Login to the worker node
  
```sh
docker exec -it tls-worker bash
```

- Get the IP address of the public interface

In Kind cluster node it's `eth0`

```sh
IP=$(ip -f inet addr show eth0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
echo $IP
```

- Start the proxy

```sh
./tls_proxy -ca /etc/kubernetes/pki/ca.crt -cert /var/lib/kubelet/pki/kubelet.crt -key /var/lib/kubelet/pki/kubelet.key -kubelet-url https://localhost:10250 -listen $IP:10250 -client-cert tls.crt  -client-key tls.key --kubelet-host tls-worker -rego --insecure
```

### Verification

- Create a test pod
  
```sh
kubectl run test --image=quay.io/fedora/fedora:39 -- "/bin/bash" "-c" "sleep 36000"
```

- Exec a shell in the pod

```sh
kubectl exec -it test -- bash
```

This will be denied and you'll see the following message

```sh
error: unable to upgrade connection: Denied by policy
```

Try `kubectl logs test` and it will be allowed.

You can tweak the policy.rego and try out additional scenarios

### Cleanup

- Delete the Kind cluster

```sh
kind delete cluster --name tls
```