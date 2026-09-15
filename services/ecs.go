package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func EnumerateECSTaskRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "ecs", []string{"AWSResource"}, map[string]interface{}{"name": "ecs"})

	for _, region := range regions {
		ecsconfig := ecs.NewFromConfig(cfg, func(o *ecs.Options) { o.Region = region })

		pager := ecs.NewListTaskDefinitionsPaginator(ecsconfig, &ecs.ListTaskDefinitionsInput{
			Status: ecstypes.TaskDefinitionStatusActive,
			Sort:   ecstypes.SortOrderDesc,
		})

		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				warn("ecs", "ListTaskDefinitions", region, err)
				break
			}
			for _, tdArn := range page.TaskDefinitionArns {
				desc, err := ecsconfig.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
					TaskDefinition: aws.String(tdArn),
					Include:        []ecstypes.TaskDefinitionField{ecstypes.TaskDefinitionFieldTags},
				})
				if err != nil {
					warn("ecs", "DescribeTaskDefinition", region, err)
					continue
				}
				if desc.TaskDefinition == nil {
					continue
				}
				td := desc.TaskDefinition

				if role := aws.ToString(td.TaskRoleArn); role != "" {
					graph.AddEdge(out, "awsEcsTaskRole", "ecs", role, map[string]interface{}{
						"name":              "awsEcsTaskRole",
						"region":            region,
						"taskDefinitionArn": tdArn,
						"family":            aws.ToString(td.Family),
						"revision":          td.Revision,
						"networkMode":       td.NetworkMode,
						"cpu":               aws.ToString(td.Cpu),
						"memory":            aws.ToString(td.Memory),
					})
				}

				if execRole := aws.ToString(td.ExecutionRoleArn); execRole != "" {
					graph.AddEdge(out, "awsEcsTaskExecutionRole", "ecs", execRole, map[string]interface{}{
						"name":              "awsEcsTaskExecutionRole",
						"region":            region,
						"taskDefinitionArn": tdArn,
						"family":            aws.ToString(td.Family),
						"revision":          td.Revision,
						"networkMode":       td.NetworkMode,
						"cpu":               aws.ToString(td.Cpu),
						"memory":            aws.ToString(td.Memory),
					})
				}
			}
		}
	}
}
