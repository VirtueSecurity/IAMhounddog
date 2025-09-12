package policies

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

type PolicyDocument struct {
	Statement []struct {
		Action    interface{}            `json:"Action"`
		Effect    string                 `json:"Effect"`
		Resource  interface{}            `json:"Resource,omitempty"`
		Principal map[string]interface{} `json:"Principal,omitempty"`
		Condition json.RawMessage        `json:"Condition,omitempty"`
	} `json:"Statement"`
}

func resourcesToStrings(res interface{}) []string {
	switch v := res.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func ParsePolicyDoc(out *graph.Output, addedResourceNodes map[string]bool, passRoleEdges map[string]map[string]bool, principalID, policyID string, docStr string) {
	var doc PolicyDocument

	if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
		return
	}

	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}
		var actions []string
		switch a := stmt.Action.(type) {
		case string:
			actions = []string{a}
		case []interface{}:
			for _, act := range a {
				if strAct, ok := act.(string); ok {
					actions = append(actions, strAct)
				}
			}
		}
		for _, act := range actions {
			parts := strings.SplitN(act, ":", 2)
			svc := parts[0]
			if svc == "" {
				svc = "*"
			}
			graph.AddNodeOnce(out, addedResourceNodes, svc, []string{"AWSResource"}, map[string]interface{}{"name": svc})

			edgeKind := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(act, "-", ""), ":", ""), "*", "AllAccess")

			graph.AddEdge(out, edgeKind, policyID, svc,
				map[string]interface{}{
					"name": edgeKind,
				})

			//special logic for passrole to create an edge from principal to role that can be passed
			if edgeKind == "iamPassRole" {
				for _, r := range resourcesToStrings(stmt.Resource) {
					if r == "" {
						continue
					}
					if passRoleEdges[principalID] == nil {
						passRoleEdges[principalID] = make(map[string]bool)
					}
					passRoleEdges[principalID][r] = true
				}
			}
		}
	}
}

func AttachPolicy(out *graph.Output, addedPolicyNodes, addedResourceNodes map[string]bool, passRoleEdges map[string]map[string]bool, principalID, policyArn, policyName string, encodedDoc string) {
	docStr, err := url.QueryUnescape(encodedDoc)
	if err != nil {
		return
	}

	graph.AddNodeOnce(
		out,
		addedPolicyNodes,
		policyArn,
		[]string{"AWSPolicy"},
		map[string]interface{}{
			"name":   policyName,
			"policy": docStr,
		},
	)
	graph.AddEdge(out, "awsAttachedPolicy", principalID, policyArn,
		map[string]interface{}{
			"name": "awsAttachedPolicy",
		})

	ParsePolicyDoc(out, addedResourceNodes, passRoleEdges, principalID, policyArn, docStr)
}
