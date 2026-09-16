package principals

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func EnumerateRoles(ctx context.Context, client *iam.Client, out *graph.Output, policyDocs map[string]string, passRoleEdges map[string]map[string]bool) {
	rolePaginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePaginator.HasMorePages() {
		rolePage, err := rolePaginator.NextPage(ctx)
		if err != nil {
			panic(err)
		}
		for _, role := range rolePage.Roles {
			roleID := aws.ToString(role.Arn)
			trustPolicy := ""
			if role.AssumeRolePolicyDocument != nil && *role.AssumeRolePolicyDocument != "" {
				if decoded, err := policies.DecodePolicyDocument(*role.AssumeRolePolicyDocument); err == nil {
					trustPolicy = decoded
				}
			}
			graph.AddNode(
				out,
				roleID,
				[]string{"AWSRole"},
				map[string]interface{}{
					"name":        aws.ToString(role.RoleName),
					"arn":         aws.ToString(role.Arn),
					"displayname": aws.ToString(role.RoleName),
					"trustPolicy": trustPolicy,
				},
			)

			// Managed policies on role
			mpPaginator := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			})
			for mpPaginator.HasMorePages() {
				mpPage, err := mpPaginator.NextPage(ctx)
				if err != nil {
					panic(err)
				}
				attachManagedPolicies(ctx, client, out, policyDocs, passRoleEdges, roleID, mpPage.AttachedPolicies)
			}

			// Inline policies on role
			rpPaginator := iam.NewListRolePoliciesPaginator(client, &iam.ListRolePoliciesInput{
				RoleName: role.RoleName,
			})
			for rpPaginator.HasMorePages() {
				rpPage, err := rpPaginator.NextPage(ctx)
				if err != nil {
					panic(err)
				}
				for _, pn := range rpPage.PolicyNames {
					gpr, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
						RoleName:   role.RoleName,
						PolicyName: aws.String(pn),
					})
					if err != nil {
						continue
					}
					inlineID := aws.ToString(role.Arn) + ":inline/" + pn
					policies.AttachPolicy(out, passRoleEdges, roleID, inlineID, pn, aws.ToString(gpr.PolicyDocument))
				}
			}
		}
	}
}
