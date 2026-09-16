package principals

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func EnumerateGroups(ctx context.Context, client *iam.Client, out *graph.Output, policyDocs map[string]string, passRoleEdges map[string]map[string]bool) {
	groupPaginator := iam.NewListGroupsPaginator(client, &iam.ListGroupsInput{})
	for groupPaginator.HasMorePages() {
		groupPage, err := groupPaginator.NextPage(ctx)
		if err != nil {
			panic(err)
		}
		for _, group := range groupPage.Groups {
			groupID := aws.ToString(group.Arn)
			graph.AddNode(
				out,
				groupID,
				[]string{"AWSGroup"},
				map[string]interface{}{
					"name":        aws.ToString(group.GroupName),
					"arn":         aws.ToString(group.Arn),
					"displayname": aws.ToString(group.GroupName),
				},
			)

			// Managed policies on group
			agp := iam.NewListAttachedGroupPoliciesPaginator(client, &iam.ListAttachedGroupPoliciesInput{
				GroupName: group.GroupName,
			})
			for agp.HasMorePages() {
				pg, err := agp.NextPage(ctx)
				if err != nil {
					panic(err)
				}
				attachManagedPolicies(ctx, client, out, policyDocs, passRoleEdges, groupID, pg.AttachedPolicies)
			}

			// Inline policies on group
			lgp := iam.NewListGroupPoliciesPaginator(client, &iam.ListGroupPoliciesInput{
				GroupName: group.GroupName,
			})
			for lgp.HasMorePages() {
				pg, err := lgp.NextPage(ctx)
				if err != nil {
					panic(err)
				}
				for _, pn := range pg.PolicyNames {
					ggp, err := client.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
						GroupName:  group.GroupName,
						PolicyName: aws.String(pn),
					})
					if err != nil {
						continue
					}
					inlineID := aws.ToString(group.Arn) + ":inline/" + pn
					policies.AttachPolicy(out, passRoleEdges, groupID, inlineID, pn, aws.ToString(ggp.PolicyDocument))
				}
			}
		}
	}
}
