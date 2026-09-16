package services

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/report"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func EnumerateLambdaExecutionRoles(ctx context.Context, cfg aws.Config, out *graph.Output, regions []string) {
	graph.AddNode(out, "lambda", []string{"AWSResource"}, map[string]interface{}{"name": "lambda"})

	for _, region := range regions {
		lambdaconfig := lambda.NewFromConfig(cfg, func(o *lambda.Options) { o.Region = region })

		pager := lambda.NewListFunctionsPaginator(lambdaconfig, &lambda.ListFunctionsInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				report.Warn("lambda", "ListFunctions", region, err)
				break
			}
			for _, fn := range page.Functions {
				roleArn := aws.ToString(fn.Role)
				if roleArn == "" {
					continue
				}
				graph.AddEdge(out, "awsLambdaInstanceRole", "lambda", roleArn,
					map[string]interface{}{
						"name":     "awsLambdaInstanceRole",
						"function": aws.ToString(fn.FunctionName),
					})
			}
		}
	}
}
