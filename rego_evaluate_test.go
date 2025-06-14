package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Minimal valid OPA policy that denies GET /forbidden
const testPolicy = `
package kubelet.policy
import rego.v1

deny if {
  input.method == "GET"
  input.path == "/forbidden"  
}
`

func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}
	return policyPath
}

func TestEvaluatePolicy_Denied(t *testing.T) {
	policyPath := writeTempPolicy(t, testPolicy)
	denied, err := evaluatePolicy(policyPath, "GET", "/forbidden")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Errorf("expected denied=true, got false")
	}
}

func TestEvaluatePolicy_Allowed(t *testing.T) {
	policyPath := writeTempPolicy(t, testPolicy)
	denied, err := evaluatePolicy(policyPath, "GET", "/allowed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Errorf("expected denied=false, got true")
	}
}

func TestEvaluatePolicy_InvalidPolicyFile(t *testing.T) {
	// Non-existent file
	_, err := evaluatePolicy("/non/existent/policy.rego", "GET", "/forbidden")
	if err == nil {
		t.Errorf("expected error for missing policy file, got nil")
	}
}

func TestEvaluatePolicy_InvalidPolicySyntax(t *testing.T) {
	policyPath := writeTempPolicy(t, "this is not valid rego")
	_, err := evaluatePolicy(policyPath, "GET", "/forbidden")
	if err == nil {
		t.Errorf("expected error for invalid policy syntax, got nil")
	}
}
