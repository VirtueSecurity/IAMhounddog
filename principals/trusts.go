package principals

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func EnumerateTrusts(ctx context.Context, client *iam.Client, out *graph.Output, passRoleEdges map[string]map[string]bool) {
	var roleARNs []string

	rolePaginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePaginator.HasMorePages() {
		rolePage, err := rolePaginator.NextPage(ctx)
		if err != nil {
			panic(err)
		}
		for _, role := range rolePage.Roles {
			roleID := aws.ToString(role.Arn)
			roleARNs = append(roleARNs, roleID)

			policies.AttachTrustRelationships(out, roleID, role.AssumeRolePolicyDocument)
		}
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
