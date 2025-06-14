package kubelet.policy

import rego.v1

# Deny requests that match these criteria
deny if {
  input.method == "POST"
  startswith(input.path, "/exec")
  reason := "POST to /exec is not allowed"
}

deny if {
  input.method == "POST"
  startswith(input.path, "/portforward")
  reason := "POST to /portforward is not allowed"
}
