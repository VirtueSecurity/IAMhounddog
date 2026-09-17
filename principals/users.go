package principals

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"
	"github.com/VirtueSecurity/IAMhounddog/report"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func EnumerateUsers(ctx context.Context, client *iam.Client, out *graph.Output, policyDocs map[string]string, passRoleEdges map[string]map[string]bool) {
	userPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPaginator.HasMorePages() {
		userPage, err := userPaginator.NextPage(ctx)
		if err != nil {
			report.Warn("iam", "ListUsers", "", err)
			break
		}
		for _, user := range userPage.Users {
			userID := aws.ToString(user.Arn)
			graph.AddNode(
				out,
				userID,
				[]string{"AWSUser"},
				map[string]interface{}{
					"name":        aws.ToString(user.UserName),
					"arn":         aws.ToString(user.Arn),
					"displayname": aws.ToString(user.UserName),
				},
			)

			// Managed policies on user
			aup := iam.NewListAttachedUserPoliciesPaginator(client, &iam.ListAttachedUserPoliciesInput{
				UserName: user.UserName,
			})
			for aup.HasMorePages() {
				pg, err := aup.NextPage(ctx)
				if err != nil {
					report.Warn("iam", "ListAttachedUserPolicies", "", err)
					break
				}
				attachManagedPolicies(ctx, client, out, policyDocs, passRoleEdges, userID, pg.AttachedPolicies)
			}

			// Inline policies on user
			lup := iam.NewListUserPoliciesPaginator(client, &iam.ListUserPoliciesInput{
				UserName: user.UserName,
			})
			for lup.HasMorePages() {
				pg, err := lup.NextPage(ctx)
				if err != nil {
					report.Warn("iam", "ListUserPolicies", "", err)
					break
				}
				for _, pn := range pg.PolicyNames {
					gup, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
						UserName:   user.UserName,
						PolicyName: aws.String(pn),
					})
					if err != nil {
						report.Warn("iam", "GetUserPolicy", "", err)
						continue
					}
					inlineID := aws.ToString(user.Arn) + ":inline/" + pn
					policies.AttachPolicy(out, passRoleEdges, userID, inlineID, pn, aws.ToString(gup.PolicyDocument))
				}
			}

			// User to Group edges
			gfu := iam.NewListGroupsForUserPaginator(client, &iam.ListGroupsForUserInput{
				UserName: user.UserName,
			})
			for gfu.HasMorePages() {
				pg, err := gfu.NextPage(ctx)
				if err != nil {
					report.Warn("iam", "ListGroupsForUser", "", err)
					break
				}
				for _, g := range pg.Groups {
					graph.AddEdge(out, "awsMemberOf", userID, aws.ToString(g.Arn),
						map[string]interface{}{
							"name": "awsMemberOf",
						})
				}
			}
		}
	}
}
