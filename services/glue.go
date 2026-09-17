package services

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/report"
)

func glueRoleTarget(out *graph.Output, byName map[string]string, value string) string {
	if value == "" || strings.HasPrefix(value, "arn:") {
		return value
	}

	if arn, ok := byName[value]; ok {
		return arn
	}

	graph.AddNode(out, value, []string{"AWSRole"}, map[string]interface{}{
		"name":       value,
		"enumerated": false,
	})

	return value
}

func EnumerateGlueRoles(ctx context.Context, cfg aws.Config, out *graph.Output, regions []string) {
	graph.AddNode(out, "glue", []string{"AWSResource"}, map[string]interface{}{"name": "glue"})

	byName := make(map[string]string)
	for _, n := range out.Graph.Nodes {
		for _, kind := range n.Kinds {
			if kind != "AWSRole" {
				continue
			}
			if name, ok := n.Properties["name"].(string); ok && name != "" {
				byName[name] = n.ID
			}
		}
	}

	for _, region := range regions {
		client := glue.NewFromConfig(cfg, func(o *glue.Options) { o.Region = region })

		jobs := glue.NewGetJobsPaginator(client, &glue.GetJobsInput{})
		for jobs.HasMorePages() {
			page, err := jobs.NextPage(ctx)
			if err != nil {
				report.Warn("glue", "GetJobs", region, err)
				break
			}

			for _, job := range page.Jobs {
				role := glueRoleTarget(out, byName, aws.ToString(job.Role))
				if role == "" {
					continue
				}

				graph.AddEdge(out, "awsGlueJobRole", "glue", role, map[string]interface{}{
					"name":        "awsGlueJobRole",
					"region":      region,
					"job":         aws.ToString(job.Name),
					"glueVersion": aws.ToString(job.GlueVersion),
				})
			}
		}

		endpoints := glue.NewGetDevEndpointsPaginator(client, &glue.GetDevEndpointsInput{})
		for endpoints.HasMorePages() {
			page, err := endpoints.NextPage(ctx)
			if err != nil {
				report.Warn("glue", "GetDevEndpoints", region, err)
				break
			}

			for _, ep := range page.DevEndpoints {
				role := glueRoleTarget(out, byName, aws.ToString(ep.RoleArn))
				if role == "" {
					continue
				}

				graph.AddEdge(out, "awsGlueDevEndpointRole", "glue", role, map[string]interface{}{
					"name":          "awsGlueDevEndpointRole",
					"region":        region,
					"devEndpoint":   aws.ToString(ep.EndpointName),
					"status":        aws.ToString(ep.Status),
					"publicAddress": aws.ToString(ep.PublicAddress),
				})
			}
		}

		crawlers := glue.NewGetCrawlersPaginator(client, &glue.GetCrawlersInput{})
		for crawlers.HasMorePages() {
			page, err := crawlers.NextPage(ctx)
			if err != nil {
				report.Warn("glue", "GetCrawlers", region, err)
				break
			}

			for _, c := range page.Crawlers {
				role := glueRoleTarget(out, byName, aws.ToString(c.Role))
				if role == "" {
					continue
				}

				graph.AddEdge(out, "awsGlueCrawlerRole", "glue", role, map[string]interface{}{
					"name":    "awsGlueCrawlerRole",
					"region":  region,
					"crawler": aws.ToString(c.Name),
				})
			}
		}
	}
}
