package policies

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func isAssumeRoleAction(a string) bool {
	a = strings.ToLower(a)
	return a == "sts:assumerole" || a == "sts:assumerolewithsaml" || a == "sts:assumerolewithwebidentity"
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

func collectPrincipalStrings(v interface{}) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = []string{t}
	case []interface{}:
		for _, x := range t {
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

		switch v := st.Principal.(type) {
		case map[string]interface{}:
			for ptype, raw := range v {
				var pvals []string
				switch strings.ToLower(ptype) {
				case "aws", "service", "federated":
					pvals = collectPrincipalStrings(raw)
				default:
					continue
				}
				for _, val := range pvals {
					start := val

					if !graph.HasAnyKind(out, val, "AWSRole", "AWSUser") {
						start = principalNodeID(ptype, val)

						graph.AddNode(out, start, []string{"AWSPrincipal"}, map[string]interface{}{
							"type": ptype,
							"name": val,
						})
					}

					graph.AddEdge(out, "awsAssumeRoleAllowed", start, roleID,
						map[string]interface{}{
							"name":      "awsAssumeRoleAllowed",
							"condition": prettyJSON(st.Condition),
						})
				}
			}
		}
	}
}
