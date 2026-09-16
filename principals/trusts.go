package principals

import (
	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func EnumerateTrusts(out *graph.Output, roles []iamtypes.Role, passRoleEdges map[string]map[string]bool) {
	roleARNs := make([]string, 0, len(roles))

	for _, role := range roles {
		roleID := aws.ToString(role.Arn)
		roleARNs = append(roleARNs, roleID)

		policies.AttachTrustRelationships(out, roleID, role.AssumeRolePolicyDocument)
	}

	for principalID, resources := range passRoleEdges {
		for resource := range resources {
			// match multiple ARNs with wildcards
			matches := policies.ResourceMatcher(resource)
			matched := false

			for _, roleARN := range roleARNs {
				if !matches(roleARN) {
					continue
				}

				matched = true
				graph.AddEdge(out, "iamPassRoleAllowed", principalID, roleARN, map[string]interface{}{
					"name":     "iamPassRoleAllowed",
					"resource": resource,
				})
			}

			// external account
			if !matched && !policies.HasWildcard(resource) {
				graph.AddNode(out, resource, []string{"AWSRole"}, map[string]interface{}{
					"name":       resource,
					"arn":        resource,
					"enumerated": false,
				})

				graph.AddEdge(out, "iamPassRoleAllowed", principalID, resource, map[string]interface{}{
					"name":     "iamPassRoleAllowed",
					"resource": resource,
				})
			}
		}
	}
}
