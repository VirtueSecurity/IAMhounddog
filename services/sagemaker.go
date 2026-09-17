package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/report"
)

func EnumerateSageMakerRoles(ctx context.Context, cfg aws.Config, out *graph.Output, regions []string) {
	graph.AddNode(out, "sagemaker", []string{"AWSResource"}, map[string]interface{}{"name": "sagemaker"})

	for _, region := range regions {
		client := sagemaker.NewFromConfig(cfg, func(o *sagemaker.Options) { o.Region = region })

		// notebook instances
		notebooks := sagemaker.NewListNotebookInstancesPaginator(client, &sagemaker.ListNotebookInstancesInput{})
		for notebooks.HasMorePages() {
			page, err := notebooks.NextPage(ctx)
			if err != nil {
				report.Warn("sagemaker", "ListNotebookInstances", region, err)
				break
			}

			for _, nb := range page.NotebookInstances {
				name := aws.ToString(nb.NotebookInstanceName)
				if name == "" {
					continue
				}

				desc, err := client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{
					NotebookInstanceName: aws.String(name),
				})
				if err != nil {
					report.Warn("sagemaker", "DescribeNotebookInstance", region, err)
					continue
				}

				if role := aws.ToString(desc.RoleArn); role != "" {
					graph.AddEdge(out, "awsSageMakerNotebookRole", "sagemaker", role, map[string]interface{}{
						"name":                 "awsSageMakerNotebookRole",
						"region":               region,
						"notebookInstance":     name,
						"notebookInstanceArn":  aws.ToString(nb.NotebookInstanceArn),
						"status":               string(nb.NotebookInstanceStatus),
						"directInternetAccess": string(desc.DirectInternetAccess),
					})
				}
			}
		}

		domains := sagemaker.NewListDomainsPaginator(client, &sagemaker.ListDomainsInput{})
		for domains.HasMorePages() {
			page, err := domains.NextPage(ctx)
			if err != nil {
				report.Warn("sagemaker", "ListDomains", region, err)
				break
			}

			for _, d := range page.Domains {
				domainID := aws.ToString(d.DomainId)
				if domainID == "" {
					continue
				}

				desc, err := client.DescribeDomain(ctx, &sagemaker.DescribeDomainInput{
					DomainId: aws.String(domainID),
				})
				if err != nil {
					report.Warn("sagemaker", "DescribeDomain", region, err)
					continue
				}

				domainRoles := map[string]string{}
				if desc.DefaultUserSettings != nil {
					domainRoles["defaultUserSettings"] = aws.ToString(desc.DefaultUserSettings.ExecutionRole)
				}
				if desc.DefaultSpaceSettings != nil {
					domainRoles["defaultSpaceSettings"] = aws.ToString(desc.DefaultSpaceSettings.ExecutionRole)
				}
				if desc.DomainSettings != nil && desc.DomainSettings.RStudioServerProDomainSettings != nil {
					domainRoles["rStudioServerPro"] = aws.ToString(desc.DomainSettings.RStudioServerProDomainSettings.DomainExecutionRoleArn)
				}

				for setting, role := range domainRoles {
					if role == "" {
						continue
					}

					graph.AddEdge(out, "awsSageMakerDomainRole", "sagemaker", role, map[string]interface{}{
						"name":     "awsSageMakerDomainRole",
						"region":   region,
						"domainId": domainID,
						"domain":   aws.ToString(desc.DomainName),
						"setting":  setting,
					})
				}
			}
		}

		// user profiles, may be bugged, can't test this properly with mock data
		profiles := sagemaker.NewListUserProfilesPaginator(client, &sagemaker.ListUserProfilesInput{})
		for profiles.HasMorePages() {
			page, err := profiles.NextPage(ctx)
			if err != nil {
				report.Warn("sagemaker", "ListUserProfiles", region, err)
				break
			}

			for _, up := range page.UserProfiles {
				domainID := aws.ToString(up.DomainId)
				name := aws.ToString(up.UserProfileName)
				if domainID == "" || name == "" {
					continue
				}

				desc, err := client.DescribeUserProfile(ctx, &sagemaker.DescribeUserProfileInput{
					DomainId:        aws.String(domainID),
					UserProfileName: aws.String(name),
				})
				if err != nil {
					report.Warn("sagemaker", "DescribeUserProfile", region, err)
					continue
				}

				if desc.UserSettings == nil {
					continue
				}

				if role := aws.ToString(desc.UserSettings.ExecutionRole); role != "" {
					graph.AddEdge(out, "awsSageMakerUserProfileRole", "sagemaker", role, map[string]interface{}{
						"name":        "awsSageMakerUserProfileRole",
						"region":      region,
						"domainId":    domainID,
						"userProfile": name,
					})
				}
			}
		}

		models := sagemaker.NewListModelsPaginator(client, &sagemaker.ListModelsInput{})
		for models.HasMorePages() {
			page, err := models.NextPage(ctx)
			if err != nil {
				report.Warn("sagemaker", "ListModels", region, err)
				break
			}

			for _, m := range page.Models {
				name := aws.ToString(m.ModelName)
				if name == "" {
					continue
				}

				desc, err := client.DescribeModel(ctx, &sagemaker.DescribeModelInput{
					ModelName: aws.String(name),
				})
				if err != nil {
					report.Warn("sagemaker", "DescribeModel", region, err)
					continue
				}

				if role := aws.ToString(desc.ExecutionRoleArn); role != "" {
					graph.AddEdge(out, "awsSageMakerModelRole", "sagemaker", role, map[string]interface{}{
						"name":     "awsSageMakerModelRole",
						"region":   region,
						"model":    name,
						"modelArn": aws.ToString(m.ModelArn),
					})
				}
			}
		}

		pipelines := sagemaker.NewListPipelinesPaginator(client, &sagemaker.ListPipelinesInput{})
		for pipelines.HasMorePages() {
			page, err := pipelines.NextPage(ctx)
			if err != nil {
				report.Warn("sagemaker", "ListPipelines", region, err)
				break
			}

			for _, pl := range page.PipelineSummaries {
				name := aws.ToString(pl.PipelineName)
				if name == "" {
					continue
				}

				desc, err := client.DescribePipeline(ctx, &sagemaker.DescribePipelineInput{
					PipelineName: aws.String(name),
				})
				if err != nil {
					report.Warn("sagemaker", "DescribePipeline", region, err)
					continue
				}

				if role := aws.ToString(desc.RoleArn); role != "" {
					graph.AddEdge(out, "awsSageMakerPipelineRole", "sagemaker", role, map[string]interface{}{
						"name":        "awsSageMakerPipelineRole",
						"region":      region,
						"pipeline":    name,
						"pipelineArn": aws.ToString(pl.PipelineArn),
					})
				}
			}
		}
	}
}
