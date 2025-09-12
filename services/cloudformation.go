package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	cfn "github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func EnumerateCloudFormationStackRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "cloudformation", []string{"AWSResource"}, map[string]interface{}{"name": "cloudformation"})

	// hack, manually add a link from s3 to cloudformation in case templates are stored in buckets that roles can edit
	graph.AddNodeOnce(out, addedResourceNodes, "s3", []string{"AWSResource"}, map[string]interface{}{"name": "s3"})
	graph.AddEdge(out, "awsS3BucketContainingCloudFormation", "s3", "cloudformation", map[string]interface{}{
		"name": "awsS3BucketContainingCloudFormation",
	})

	activeStatuses := []cfntypes.StackStatus{
		cfntypes.StackStatusCreateInProgress,
		cfntypes.StackStatusCreateComplete,
		cfntypes.StackStatusCreateFailed,
		cfntypes.StackStatusRollbackInProgress,
		cfntypes.StackStatusRollbackFailed,
		cfntypes.StackStatusRollbackComplete,
		cfntypes.StackStatusDeleteInProgress,
		cfntypes.StackStatusDeleteFailed,
		cfntypes.StackStatusUpdateInProgress,
		cfntypes.StackStatusUpdateCompleteCleanupInProgress,
		cfntypes.StackStatusUpdateComplete,
		cfntypes.StackStatusUpdateRollbackInProgress,
		cfntypes.StackStatusUpdateRollbackFailed,
		cfntypes.StackStatusUpdateRollbackCompleteCleanupInProgress,
		cfntypes.StackStatusUpdateRollbackComplete,
		cfntypes.StackStatusReviewInProgress,
		cfntypes.StackStatusImportInProgress,
		cfntypes.StackStatusImportComplete,
		cfntypes.StackStatusImportRollbackInProgress,
		cfntypes.StackStatusImportRollbackFailed,
		cfntypes.StackStatusImportRollbackComplete,
	}

	for _, region := range regions {
		cfconfig := cfn.NewFromConfig(cfg, func(o *cfn.Options) { o.Region = region })

		pager := cfn.NewListStacksPaginator(cfconfig, &cfn.ListStacksInput{
			StackStatusFilter: activeStatuses,
		})

		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, s := range page.StackSummaries {
				desc, err := cfconfig.DescribeStacks(ctx, &cfn.DescribeStacksInput{})
				if err != nil || len(desc.Stacks) == 0 {
					continue
				}
				st := desc.Stacks[0]
				roleArn := aws.ToString(st.RoleARN)
				if roleArn == "" {
					continue
				}

				graph.AddEdge(out, "awsCloudFormationStackRole", "cloudformation", roleArn, map[string]interface{}{
					"name":     "awsCloudFormationStackRole",
					"stack":    aws.ToString(st.StackName),
					"stackId":  aws.ToString(st.StackId),
					"region":   region,
					"parentId": aws.ToString(s.ParentId),
				})
			}
		}
	}
}
