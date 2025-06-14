package kubelet.policy

import rego.v1

# Deny requests that match these criteria
deny if {
  input.method == "POST"
  startswith(input.path, "/exec")  
}

deny if {
  input.method == "POST"
  startswith(input.path, "/portForward")  
}

deny if {
  input.method == "POST"
  startswith(input.path, "/attach") 
}