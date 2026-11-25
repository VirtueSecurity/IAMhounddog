package policies

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func isAssumeRoleAction(a string) bool {
	match := ResourceMatcher(strings.ToLower(strings.TrimSpace(a)))

	return match("sts:assumerole") ||
		match("sts:assumerolewithsaml") ||
		match("sts:assumerolewithwebidentity")
}

func collectActions(val interface{}) []string {
	var out []string
	switch v := val.(type) {
	case string:
		out = []string{v}
	case []interface{}:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func prettyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// serviceResourceEdge describes the AWSResource node and edge kind that
// represents an AWS service being able to instantiate (assume) a role
type serviceResourceEdge struct {
	resource string
	edgeKind string
}

// serviceResourceEdges maps a lower-cased service principal to the resource
// edge it should produce when a role trusts it.
var serviceResourceEdges = map[string]serviceResourceEdge{
	"braket.amazonaws.com": {resource: "braket", edgeKind: "awsBraketJobRole"},
}

func AttachTrustRelationships(out *graph.Output, roleID string, encodedDoc *string) {
	if encodedDoc == nil || *encodedDoc == "" {
		return
	}
	docStr, err := DecodePolicyDocument(*encodedDoc)
	if err != nil {
		return
	}
	var doc PolicyDocument
	if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
		return
	}

	for _, st := range doc.Statement {
		if strings.ToLower(st.Effect) != "allow" {
			continue
		}
		assume := false
		for _, a := range collectActions(st.Action) {
			if isAssumeRoleAction(a) {
				assume = true
				break
			}
		}
		if !assume {
			continue
		}

		for _, p := range collectTypedPrincipals(st.Principal) {
			switch strings.ToLower(p.ptype) {
			case "aws", "service", "federated":
			default:
				continue
			}

			start := p.value

			if !graph.HasAnyKind(out, p.value, "AWSRole", "AWSUser") {
				start = principalNodeID(p.ptype, p.value)

				graph.AddNode(out, start, []string{"AWSPrincipal"}, map[string]interface{}{
					"type": p.ptype,
					"name": p.value,
				})
			}

			graph.AddEdge(out, "awsAssumeRoleAllowed", start, roleID,
				map[string]interface{}{
					"name":      "awsAssumeRoleAllowed",
					"condition": prettyJSON(st.Condition),
				})

			// When a role trusts a known service principal, also link the
			// service resource to the role
			if strings.EqualFold(p.ptype, "service") {
				if sre, ok := serviceResourceEdges[strings.ToLower(strings.TrimSpace(p.value))]; ok {
					graph.AddNode(out, sre.resource, []string{"AWSResource"},
						map[string]interface{}{"name": sre.resource})

					graph.AddEdge(out, sre.edgeKind, sre.resource, roleID,
						map[string]interface{}{
							"name":      sre.edgeKind,
							"condition": prettyJSON(st.Condition),
						})
				}
			}
		}
	}
}
