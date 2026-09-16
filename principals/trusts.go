package principals

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func EnumerateTrusts(ctx context.Context, client *iam.Client, out *graph.Output, passRoleEdges map[string]map[string]bool) {
	rolePaginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePaginator.HasMorePages() {
		rolePage, err := rolePaginator.NextPage(ctx)
		if err != nil {
			panic(err)
		}
		for _, role := range rolePage.Roles {
			roleID := aws.ToString(role.Arn)

			policies.AttachTrustRelationships(out, roleID, role.AssumeRolePolicyDocument)
		}
	}

	for principalID, resources := range passRoleEdges {
		for resource := range resources {
			graph.AddEdge(out, "iamPassRoleAllowed", principalID, resource, map[string]interface{}{
				"name": "iamPassRoleAllowed",
			})
		}
	}
}
