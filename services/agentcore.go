package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	agentcore "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/report"
)

func EnumerateBedrockAgentCore(ctx context.Context, cfg aws.Config, out *graph.Output, regions []string) {
	graph.AddNode(out, "bedrock-agentcore", []string{"AWSResource"}, map[string]interface{}{"name": "bedrock-agentcore"})

	for _, region := range regions {
		client := agentcore.NewFromConfig(cfg, func(o *agentcore.Options) { o.Region = region })

		runtimes := agentcore.NewListAgentRuntimesPaginator(client, &agentcore.ListAgentRuntimesInput{})
		for runtimes.HasMorePages() {
			page, err := runtimes.NextPage(ctx)
			if err != nil {
				report.Warn("bedrock-agentcore", "ListAgentRuntimes", region, err)
				break
			}

			for _, rt := range page.AgentRuntimes {
				id := aws.ToString(rt.AgentRuntimeId)
				if id == "" {
					continue
				}

				desc, err := client.GetAgentRuntime(ctx, &agentcore.GetAgentRuntimeInput{
					AgentRuntimeId: aws.String(id),
				})
				if err != nil {
					report.Warn("bedrock-agentcore", "GetAgentRuntime", region, err)
					continue
				}

				if role := aws.ToString(desc.RoleArn); role != "" {
					graph.AddEdge(out, "awsAgentCoreRuntimeRole", "bedrock-agentcore", role, map[string]interface{}{
						"name":            "awsAgentCoreRuntimeRole",
						"region":          region,
						"agentRuntimeId":  id,
						"agentRuntime":    aws.ToString(rt.AgentRuntimeName),
						"agentRuntimeArn": aws.ToString(rt.AgentRuntimeArn),
						"status":          string(rt.Status),
					})
				}
			}
		}

		gateways := agentcore.NewListGatewaysPaginator(client, &agentcore.ListGatewaysInput{})
		for gateways.HasMorePages() {
			page, err := gateways.NextPage(ctx)
			if err != nil {
				report.Warn("bedrock-agentcore", "ListGateways", region, err)
				break
			}

			for _, gw := range page.Items {
				id := aws.ToString(gw.GatewayId)
				if id == "" {
					continue
				}

				desc, err := client.GetGateway(ctx, &agentcore.GetGatewayInput{
					GatewayIdentifier: aws.String(id),
				})
				if err != nil {
					report.Warn("bedrock-agentcore", "GetGateway", region, err)
					continue
				}

				if role := aws.ToString(desc.RoleArn); role != "" {
					graph.AddEdge(out, "awsAgentCoreGatewayRole", "bedrock-agentcore", role, map[string]interface{}{
						"name":           "awsAgentCoreGatewayRole",
						"region":         region,
						"gatewayId":      id,
						"gateway":        aws.ToString(gw.Name),
						"protocolType":   string(gw.ProtocolType),
						"authorizerType": string(gw.AuthorizerType),
					})
				}
			}
		}

		interpreters := agentcore.NewListCodeInterpretersPaginator(client, &agentcore.ListCodeInterpretersInput{})
		for interpreters.HasMorePages() {
			page, err := interpreters.NextPage(ctx)
			if err != nil {
				report.Warn("bedrock-agentcore", "ListCodeInterpreters", region, err)
				break
			}

			for _, ci := range page.CodeInterpreterSummaries {
				id := aws.ToString(ci.CodeInterpreterId)
				if id == "" {
					continue
				}

				desc, err := client.GetCodeInterpreter(ctx, &agentcore.GetCodeInterpreterInput{
					CodeInterpreterId: aws.String(id),
				})
				if err != nil {
					report.Warn("bedrock-agentcore", "GetCodeInterpreter", region, err)
					continue
				}

				if role := aws.ToString(desc.ExecutionRoleArn); role != "" {
					graph.AddEdge(out, "awsAgentCoreCodeInterpreterRole", "bedrock-agentcore", role, map[string]interface{}{
						"name":              "awsAgentCoreCodeInterpreterRole",
						"region":            region,
						"codeInterpreterId": id,
						"codeInterpreter":   aws.ToString(ci.Name),
					})
				}
			}
		}

		browsers := agentcore.NewListBrowsersPaginator(client, &agentcore.ListBrowsersInput{})
		for browsers.HasMorePages() {
			page, err := browsers.NextPage(ctx)
			if err != nil {
				report.Warn("bedrock-agentcore", "ListBrowsers", region, err)
				break
			}

			for _, br := range page.BrowserSummaries {
				id := aws.ToString(br.BrowserId)
				if id == "" {
					continue
				}

				desc, err := client.GetBrowser(ctx, &agentcore.GetBrowserInput{
					BrowserId: aws.String(id),
				})
				if err != nil {
					report.Warn("bedrock-agentcore", "GetBrowser", region, err)
					continue
				}

				if role := aws.ToString(desc.ExecutionRoleArn); role != "" {
					graph.AddEdge(out, "awsAgentCoreBrowserRole", "bedrock-agentcore", role, map[string]interface{}{
						"name":      "awsAgentCoreBrowserRole",
						"region":    region,
						"browserId": id,
						"browser":   aws.ToString(br.Name),
					})
				}
			}
		}
	}
}
