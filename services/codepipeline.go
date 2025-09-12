package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func EnumerateCodePipelineRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "codepipeline", []string{"AWSResource"}, map[string]interface{}{"name": "codepipeline"})

	// hack, manually add a link from s3 to codepipline in case pipelines are stored in buckets that roles can edit
	graph.AddNodeOnce(out, addedResourceNodes, "s3", []string{"AWSResource"}, map[string]interface{}{"name": "s3"})
	graph.AddEdge(out, "awsS3BucketContainingCodePipeline", "s3", "codepipeline", map[string]interface{}{
		"name": "awsS3BucketContainingCodePipeline",
	})

	for _, region := range regions {
		cpconfig := codepipeline.NewFromConfig(cfg, func(o *codepipeline.Options) { o.Region = region })

		pager := codepipeline.NewListPipelinesPaginator(cpconfig, &codepipeline.ListPipelinesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, summary := range page.Pipelines {
				name := aws.ToString(summary.Name)
				if name == "" {
					continue
				}

				pOut, err := cpconfig.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: aws.String(name)})
				if err != nil || pOut.Pipeline == nil {
					continue
				}
				roleArn := aws.ToString(pOut.Pipeline.RoleArn)
				if roleArn == "" {
					continue
				}

				graph.AddEdge(out, "awsCodePipelineRole", "codepipeline", roleArn, map[string]interface{}{
					"name":     "awsCodePipelineRole",
					"pipeline": name,
					"region":   region,
				})
			}
		}
	}
}
