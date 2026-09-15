package principals

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func fetchPolicyDocument(ctx context.Context, client *iam.Client, policyArn string) string {
	pd, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &policyArn})
	if err != nil || pd.Policy == nil || pd.Policy.DefaultVersionId == nil {
		return ""
	}

	ver, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: pd.Policy.DefaultVersionId,
	})
	if err != nil || ver.PolicyVersion == nil || ver.PolicyVersion.Document == nil {
		return ""
	}

	return aws.ToString(ver.PolicyVersion.Document)
}

func attachManagedPolicies(ctx context.Context, client *iam.Client, out *graph.Output, addedPolicyNodes, addedResourceNodes map[string]bool, policyDocs map[string]string, passRoleEdges map[string]map[string]bool, principalID string, attached []iamtypes.AttachedPolicy) {
	for _, mp := range attached {
		pArn := aws.ToString(mp.PolicyArn)
		pName := aws.ToString(mp.PolicyName)

		doc, cached := policyDocs[pArn]
		if !cached {
			doc = fetchPolicyDocument(ctx, client, pArn)
			policyDocs[pArn] = doc
		}
		if doc == "" {
			continue
		}

		policies.AttachPolicy(out, addedPolicyNodes, addedResourceNodes, passRoleEdges, principalID, pArn, pName, doc)
	}
}
