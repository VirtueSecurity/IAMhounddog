package principals

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func EnumerateRoles(ctx context.Context, client *iam.Client, out *graph.Output, addedPolicyNodes, addedResourceNodes map[string]bool, passRoleEdges map[string]map[string]bool) {
	rolePaginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePaginator.HasMorePages() {
		rolePage, err := rolePaginator.NextPage(ctx)
		if err != nil {
			panic(err)
		}
		for _, role := range rolePage.Roles {
			roleID := aws.ToString(role.Arn)
			graph.AddNode(
				out,
				roleID,
				[]string{"AWSRole"},
				map[string]interface{}{
					"name":        aws.ToString(role.RoleName),
					"arn":         aws.ToString(role.Arn),
					"displayname": aws.ToString(role.RoleName),
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
				for _, mp := range mpPage.AttachedPolicies {
					pArn := aws.ToString(mp.PolicyArn)
					pName := aws.ToString(mp.PolicyName)

					pd, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &pArn})
					if err != nil || pd.Policy == nil || pd.Policy.DefaultVersionId == nil {
						continue
					}
					ver, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
						PolicyArn: &pArn,
						VersionId: pd.Policy.DefaultVersionId,
					})
					if err != nil || ver.PolicyVersion == nil || ver.PolicyVersion.Document == nil {
						continue
					}

					policies.AttachPolicy(out, addedPolicyNodes, addedResourceNodes, passRoleEdges, roleID, pArn, pName, aws.ToString(ver.PolicyVersion.Document))
				}
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
					policies.AttachPolicy(out, addedPolicyNodes, addedResourceNodes, passRoleEdges, roleID, inlineID, pn, aws.ToString(gpr.PolicyDocument))
				}
			}
		}
	}
}
