package services

import (
	"context"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func EnumerateEKSRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "eks", []string{"AWSResource"}, map[string]interface{}{"name": "eks"})

	for _, region := range regions {
		eksconfig := eks.NewFromConfig(cfg, func(o *eks.Options) { o.Region = region })

		clPager := eks.NewListClustersPaginator(eksconfig, &eks.ListClustersInput{})
		for clPager.HasMorePages() {
			clPage, err := clPager.NextPage(ctx)
			if err != nil {
				warn("eks", "ListClusters", region, err)
				break
			}
			for _, clusterName := range clPage.Clusters {
				clOut, err := eksconfig.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(clusterName)})
				if err != nil {
					warn("eks", "DescribeCluster", region, err)
				}
				if err == nil && clOut.Cluster != nil {
					roleArn := aws.ToString(clOut.Cluster.RoleArn)
					if roleArn != "" {
						graph.AddEdge(out, "awsEksClusterRole", "eks", roleArn, map[string]interface{}{
							"name":    "awsEksClusterRole",
							"cluster": clusterName,
							"region":  region,
						})
					}
				}

				ngPager := eks.NewListNodegroupsPaginator(eksconfig, &eks.ListNodegroupsInput{
					ClusterName: aws.String(clusterName),
				})
				for ngPager.HasMorePages() {
					ngPage, err := ngPager.NextPage(ctx)
					if err != nil {
						warn("eks", "ListNodegroups", region, err)
						break
					}
					for _, ngName := range ngPage.Nodegroups {
						ngOut, err := eksconfig.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
							ClusterName:   aws.String(clusterName),
							NodegroupName: aws.String(ngName),
						})
						if err != nil {
							warn("eks", "DescribeNodegroup", region, err)
							continue
						}
						if ngOut.Nodegroup == nil {
							continue
						}
						nodeRole := aws.ToString(ngOut.Nodegroup.NodeRole)
						if nodeRole != "" {
							graph.AddEdge(out, "awsEksNodeRole", "eks", nodeRole, map[string]interface{}{
								"name":      "awsEksNodeRole",
								"cluster":   clusterName,
								"nodegroup": ngName,
								"region":    region,
							})
						}
					}
				}
			}
		}
	}
}
