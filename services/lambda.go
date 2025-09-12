package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func EnumerateLambdaExecutionRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "lambda", []string{"AWSResource"}, map[string]interface{}{"name": "lambda"})

	for _, region := range regions {
		lambdaconfig := lambda.NewFromConfig(cfg, func(o *lambda.Options) { o.Region = region })

		pager := lambda.NewListFunctionsPaginator(lambdaconfig, &lambda.ListFunctionsInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
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
