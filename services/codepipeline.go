package services

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	cpTypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func addCodePipelineArtifactStoreEdges(out *graph.Output, addedResourceNodes map[string]bool, store *cpTypes.ArtifactStore, pipelineName string) {
	if store == nil {
		return
	}

	if store.Type != cpTypes.ArtifactStoreTypeS3 {
		return
	}

	bucketName := aws.ToString(store.Location)
	if bucketName == "" {
		return
	}

	bucketArn := fmt.Sprintf("arn:aws:s3:::%s", bucketName)

	graph.AddNodeOnce(out, addedResourceNodes, bucketArn, []string{"AWSResource"}, map[string]interface{}{
		"name":       bucketName,
		"arn":        bucketArn,
		"artifactOf": pipelineName,
	})

	graph.AddEdge(out, "awsCodePipelineS3ArtifactStore", "codepipeline", bucketArn, map[string]interface{}{
		"name":      "awsCodePipelineS3ArtifactStore",
		"bucket":    bucketName,
		"bucketArn": bucketArn,
		"pipeline":  pipelineName,
	})
}

func EnumerateCodePipelineRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "codepipeline", []string{"AWSResource"}, map[string]interface{}{"name": "codepipeline"})

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
				if roleArn != "" {
					graph.AddEdge(out, "awsCodePipelineRole", "codepipeline", roleArn, map[string]interface{}{
						"name":     "awsCodePipelineRole",
						"pipeline": name,
						"region":   region,
					})
				}

				if pOut.Pipeline.ArtifactStore != nil {
					addCodePipelineArtifactStoreEdges(out, addedResourceNodes, pOut.Pipeline.ArtifactStore, name)
				}

				for _, store := range pOut.Pipeline.ArtifactStores {
					addCodePipelineArtifactStoreEdges(out, addedResourceNodes, &store, name)
				}
			}
		}
	}
}
