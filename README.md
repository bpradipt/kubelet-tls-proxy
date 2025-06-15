# Introduction

This is an experimental project introducing policy based validation for Kubelet APIs.
The motivation for this approach is to explore the possibility of creating confidential Kubernetes worker nodes
where the control plane is untrusted.

The policy based validation is inspired from Kata agent](https://github.com/kata-containers/kata-containers/blob/main/docs/how-to/how-to-use-the-kata-agent-policy.md).

## Build

```sh
make build
```

## Running

In order to use the TLS proxy you must ensure the following:

- The `kubelet` must be running on `localhost`. IOW, the `address` field in the `kubelet` [configuration](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/#create-the-config-file) must be `localhost`.
- The TLS proxy must be running on the public interface for kube-api-server to connect to.
- Use the same `kubelet` port for the TLS proxy as configured in the `kubelet` configuration (default port: 10250).


