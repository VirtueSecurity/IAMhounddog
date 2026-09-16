package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/report"
)

func EnumerateStepFunctionRoles(ctx context.Context, cfg aws.Config, out *graph.Output, regions []string) {
	graph.AddNode(out, "states", []string{"AWSResource"}, map[string]interface{}{"name": "states"})

	for _, region := range regions {
		sfconfig := sfn.NewFromConfig(cfg, func(o *sfn.Options) { o.Region = region })

		pager := sfn.NewListStateMachinesPaginator(sfconfig, &sfn.ListStateMachinesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				report.Warn("states", "ListStateMachines", region, err)
				break
			}
			for _, sm := range page.StateMachines {
				desc, err := sfconfig.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
					StateMachineArn: sm.StateMachineArn,
				})
				if err != nil {
					report.Warn("states", "DescribeStateMachine", region, err)
					continue
				}
				if desc == nil {
					continue
				}

				roleArn := aws.ToString(desc.RoleArn)
				if roleArn == "" {
					continue
				}

				graph.AddEdge(out, "awsStateMachineRole", "states", roleArn, map[string]interface{}{
					"name":             "awsStateMachineRole",
					"region":           region,
					"stateMachineArn":  aws.ToString(sm.StateMachineArn),
					"stateMachineName": aws.ToString(sm.Name),
					"type":             string(desc.Type),
					"status":           string(desc.Status),
				})
			}
		}
	}
}
