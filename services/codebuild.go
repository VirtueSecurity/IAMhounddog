package services

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
)

func EnumerateCodeBuildProjectRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "codebuild", []string{"AWSResource"}, map[string]interface{}{"name": "codebuild"})

	for _, region := range regions {
		cbconfig := codebuild.NewFromConfig(cfg, func(o *codebuild.Options) { o.Region = region })

		pager := codebuild.NewListProjectsPaginator(cbconfig, &codebuild.ListProjectsInput{})
		var names []string
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			names = append(names, page.Projects...)
		}

		if len(names) == 0 {
			continue
		}

		bg, err := cbconfig.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: names[0:],
		})

		if err != nil {
			continue
		}
		for _, proj := range bg.Projects {
			roleArn := aws.ToString(proj.ServiceRole)
			if roleArn == "" {
				continue
			}
			graph.AddEdge(out, "awsCodeBuildProjectRole", "codebuild", roleArn, map[string]interface{}{
				"name":       "awsCodeBuildProjectRole",
				"project":    aws.ToString(proj.Name),
				"projectArn": aws.ToString(proj.Arn),
			})
		}
	}
}
