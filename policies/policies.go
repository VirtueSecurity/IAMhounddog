package policies

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

type Statement struct {
	Action    interface{}     `json:"Action"`
	Effect    string          `json:"Effect"`
	Resource  interface{}     `json:"Resource,omitempty"`
	Principal interface{}     `json:"Principal,omitempty"`
	Condition json.RawMessage `json:"Condition,omitempty"`
}

type StatementList []Statement

type typedPrincipal struct {
	ptype string
	value string
}

func (l *StatementList) UnmarshalJSON(data []byte) error {
	var list []Statement
	if err := json.Unmarshal(data, &list); err == nil {
		*l = list
		return nil
	}

	var single Statement
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}

	*l = StatementList{single}
	return nil
}

type PolicyDocument struct {
	Statement StatementList `json:"Statement"`
}

// QueryUnescape decodes '+' to a space, so use PathUnescape instead
func DecodePolicyDocument(encoded string) (string, error) {
	return url.PathUnescape(encoded)
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

func normalizeAction(act string) (svc, edgeKind string) {
	parts := strings.SplitN(act, ":", 2)

	svc = strings.ToLower(parts[0])
	if svc == "" {
		svc = "*"
	}

	name := ""
	if len(parts) == 2 {
		name = parts[1]
	}

	edgeKind = strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(svc+name, "-", ""), ":", ""), "*", "AllAccess")

	return svc, edgeKind
}

func ParsePolicyDoc(out *graph.Output, passRoleEdges map[string]map[string]bool, principalID, policyID string, docStr string, emitActionEdges bool) {
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
			svc, edgeKind := normalizeAction(act)

			if emitActionEdges {
				graph.AddNode(out, svc, []string{"AWSResource"}, map[string]interface{}{"name": svc})

				graph.AddEdge(out, edgeKind, policyID, svc,
					map[string]interface{}{
						"name": edgeKind,
					})
			}

			//special logic for passrole to create an edge from principal to role that can be passed
			if strings.EqualFold(strings.TrimSpace(act), "iam:PassRole") {
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

func AttachPolicy(out *graph.Output, passRoleEdges map[string]map[string]bool, principalID, policyArn, policyName string, encodedDoc string) {
	docStr, err := DecodePolicyDocument(encodedDoc)
	if err != nil {
		return
	}

	firstSighting := graph.AddNode(
		out,
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

	ParsePolicyDoc(out, passRoleEdges, principalID, policyArn, docStr, firstSighting)
}

// helper function to ensure trust policies and bucket policies agree on format
func principalNodeID(ptype, value string) string {
	return "principal:" + strings.ToLower(ptype) + ":" + value
}

func collectTypedPrincipals(v interface{}) []typedPrincipal {
	var out []typedPrincipal

	switch t := v.(type) {
	case string:
		out = append(out, typedPrincipal{ptype: "AWS", value: t})
	case map[string]interface{}:
		for ptype, raw := range t {
			switch vv := raw.(type) {
			case string:
				out = append(out, typedPrincipal{ptype: ptype, value: vv})
			case []interface{}:
				for _, el := range vv {
					if s, ok := el.(string); ok {
						out = append(out, typedPrincipal{ptype: ptype, value: s})
					}
				}
			}
		}
	}

	return out
}

func ParseS3PolicyDoc(out *graph.Output, bucketArn, docStr string) {
	var doc PolicyDocument

	if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
		return
	}

	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		principals := collectTypedPrincipals(stmt.Principal)

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

		for _, p := range principals {
			start := p.value

			if !graph.HasAnyKind(out, start, "AWSRole", "AWSUser") {
				start = principalNodeID(p.ptype, p.value)

				graph.AddNode(out, start, []string{"AWSPrincipal"}, map[string]interface{}{
					"type": p.ptype,
					"name": p.value,
				})
			}

			for _, act := range actions {
				_, edgeKind := normalizeAction(act)

				graph.AddEdge(out, edgeKind, start, bucketArn, map[string]interface{}{
					"name": edgeKind,
				})
			}
		}
	}
}
