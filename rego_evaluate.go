package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/open-policy-agent/opa/v1/rego"
)

type RequestInput struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func evaluatePolicy(policyPath, method, path string) (bool, error) {

	policy, err := os.ReadFile(policyPath)
	if err != nil {
		return false, fmt.Errorf("failed to read policy file: %w", err)
	}

	ctx := context.Background()
	query, err := rego.New(
		rego.Query("data.kubelet.policy.deny"),
		rego.Module(policyPath, string(policy)),
	).PrepareForEval(ctx)
	if err != nil {
		return false, err
	}

	input := RequestInput{
		Method: method,
		Path:   path,
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, err
	}

	//bytes, _ := json.Marshal(rs)
	//fmt.Fprintf(os.Stdout, "%s\n", string(bytes))

	if len(rs) > 0 && len(rs[0].Expressions) > 0 && rs[0].Expressions[0].Value.(bool) {
		log.Printf("[POLICY] Denied path: %s", path)
		return true, nil
	} else {
		log.Printf("[POLICY] Allowed path: %s", path)
	}

	return false, nil
}
