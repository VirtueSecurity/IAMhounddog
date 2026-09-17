package principals

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"
	"github.com/VirtueSecurity/IAMhounddog/report"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func attachManagedPolicies(ctx context.Context, client *iam.Client, out *graph.Output, policyDocs map[string]string, passRoleEdges map[string]map[string]bool, principalID string, attached []iamtypes.AttachedPolicy) {
	for _, mp := range attached {
		pArn := aws.ToString(mp.PolicyArn)
		pName := aws.ToString(mp.PolicyName)

		doc, cached := policyDocs[pArn]
		if !cached {
			pd, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &pArn})
			if err != nil {
				report.Warn("iam", "GetPolicy", "", err)
			} else if pd.Policy != nil && pd.Policy.DefaultVersionId != nil {
				ver, verErr := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
					PolicyArn: &pArn,
					VersionId: pd.Policy.DefaultVersionId,
				})
				if verErr != nil {
					report.Warn("iam", "GetPolicyVersion", "", verErr)
				} else if ver.PolicyVersion != nil {
					doc = aws.ToString(ver.PolicyVersion.Document)
				}
			}

			policyDocs[pArn] = doc
		}
		if doc == "" {
			continue
		}

		policies.AttachPolicy(out, passRoleEdges, principalID, pArn, pName, doc)
	}
}
