package services

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/report"
)

func cognitoRoleEdge(key string) string {
	if strings.EqualFold(key, "unauthenticated") {
		return "awsCognitoUnauthenticatedRole"
	}

	return "awsCognitoAuthenticatedRole"
}

func EnumerateCognitoIdentityPools(ctx context.Context, cfg aws.Config, out *graph.Output, regions []string) {
	graph.AddNode(out, "cognito-identity", []string{"AWSResource"}, map[string]interface{}{"name": "cognito-identity"})

	for _, region := range regions {
		client := cognitoidentity.NewFromConfig(cfg, func(o *cognitoidentity.Options) { o.Region = region })

		pager := cognitoidentity.NewListIdentityPoolsPaginator(client, &cognitoidentity.ListIdentityPoolsInput{
			MaxResults: aws.Int32(60),
		})

		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				report.Warn("cognito-identity", "ListIdentityPools", region, err)
				break
			}

			for _, summary := range page.IdentityPools {
				poolID := aws.ToString(summary.IdentityPoolId)
				if poolID == "" {
					continue
				}

				desc, err := client.DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{
					IdentityPoolId: aws.String(poolID),
				})
				if err != nil {
					report.Warn("cognito-identity", "DescribeIdentityPool", region, err)
					continue
				}

				graph.AddNode(out, poolID, []string{"AWSResource"}, map[string]interface{}{
					"name":                           aws.ToString(desc.IdentityPoolName),
					"identityPoolId":                 poolID,
					"region":                         region,
					"allowUnauthenticatedIdentities": desc.AllowUnauthenticatedIdentities,
					"allowClassicFlow":               aws.ToBool(desc.AllowClassicFlow),
				})

				graph.AddEdge(out, "awsCognitoIdentityPool", "cognito-identity", poolID, map[string]interface{}{
					"name":                           "awsCognitoIdentityPool",
					"region":                         region,
					"identityPool":                   aws.ToString(desc.IdentityPoolName),
					"allowUnauthenticatedIdentities": desc.AllowUnauthenticatedIdentities,
				})

				for _, provider := range desc.CognitoIdentityProviders {
					graph.AddNode(out, "cognito-idp", []string{"AWSResource"}, map[string]interface{}{"name": "cognito-idp"})

					graph.AddEdge(out, "awsCognitoUserPoolProvider", "cognito-idp", poolID, map[string]interface{}{
						"name":     "awsCognitoUserPoolProvider",
						"region":   region,
						"provider": aws.ToString(provider.ProviderName),
						"clientId": aws.ToString(provider.ClientId),
					})
				}

				poolRoles, err := client.GetIdentityPoolRoles(ctx, &cognitoidentity.GetIdentityPoolRolesInput{
					IdentityPoolId: aws.String(poolID),
				})
				if err != nil {
					report.Warn("cognito-identity", "GetIdentityPoolRoles", region, err)
					continue
				}

				for key, roleArn := range poolRoles.Roles {
					if roleArn == "" {
						continue
					}

					graph.AddEdge(out, cognitoRoleEdge(key), poolID, roleArn, map[string]interface{}{
						"name":                           cognitoRoleEdge(key),
						"region":                         region,
						"identityPool":                   aws.ToString(desc.IdentityPoolName),
						"allowUnauthenticatedIdentities": desc.AllowUnauthenticatedIdentities,
					})
				}

				for provider, mapping := range poolRoles.RoleMappings {
					if mapping.RulesConfiguration == nil {
						continue
					}

					for _, rule := range mapping.RulesConfiguration.Rules {
						roleArn := aws.ToString(rule.RoleARN)
						if roleArn == "" {
							continue
						}

						graph.AddEdge(out, "awsCognitoMappedRole", poolID, roleArn, map[string]interface{}{
							"name":         "awsCognitoMappedRole",
							"region":       region,
							"identityPool": aws.ToString(desc.IdentityPoolName),
							"provider":     provider,
							"claim":        aws.ToString(rule.Claim),
							"matchType":    string(rule.MatchType),
							"value":        aws.ToString(rule.Value),
						})
					}
				}
			}
		}
	}
}
