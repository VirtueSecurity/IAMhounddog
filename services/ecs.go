package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func ecsTaskDefProps(td *ecstypes.TaskDefinition, region, edgeName string) map[string]interface{} {
	return map[string]interface{}{
		"name":              edgeName,
		"region":            region,
		"taskDefinitionArn": aws.ToString(td.TaskDefinitionArn),
		"family":            aws.ToString(td.Family),
		"revision":          td.Revision,
		"networkMode":       td.NetworkMode,
		"cpu":               aws.ToString(td.Cpu),
		"memory":            aws.ToString(td.Memory),
	}
}

func EnumerateECSTaskRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "ecs", []string{"AWSResource"}, map[string]interface{}{"name": "ecs"})

	for _, region := range regions {
		ecsconfig := ecs.NewFromConfig(cfg, func(o *ecs.Options) { o.Region = region })

		pager := ecs.NewListTaskDefinitionFamiliesPaginator(ecsconfig, &ecs.ListTaskDefinitionFamiliesInput{
			Status: ecstypes.TaskDefinitionFamilyStatusActive,
		})

		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				warn("ecs", "ListTaskDefinitionFamilies", region, err)
				break
			}
			for _, family := range page.Families {
				desc, err := ecsconfig.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
					TaskDefinition: aws.String(family),
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
					graph.AddEdge(out, "awsEcsTaskRole", "ecs", role, ecsTaskDefProps(td, region, "awsEcsTaskRole"))
				}

				if execRole := aws.ToString(td.ExecutionRoleArn); execRole != "" {
					graph.AddEdge(out, "awsEcsTaskExecutionRole", "ecs", execRole, ecsTaskDefProps(td, region, "awsEcsTaskExecutionRole"))
				}
			}
		}
	}
}
