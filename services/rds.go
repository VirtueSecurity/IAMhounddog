package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func EnumerateRDSRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "rds", []string{"AWSResource"}, map[string]interface{}{"name": "rds"})

	for _, region := range regions {
		rdsconfig := rds.NewFromConfig(cfg, func(o *rds.Options) { o.Region = region })

		instPager := rds.NewDescribeDBInstancesPaginator(rdsconfig, &rds.DescribeDBInstancesInput{})
		for instPager.HasMorePages() {
			page, err := instPager.NextPage(ctx)
			if err != nil {
				warn("rds", "DescribeDBInstances", region, err)
				break
			}
			for _, inst := range page.DBInstances {
				instID := aws.ToString(inst.DBInstanceIdentifier)
				engine := aws.ToString(inst.Engine)

				if mArn := aws.ToString(inst.MonitoringRoleArn); mArn != "" {
					graph.AddEdge(out, "awsRdsMonitoringRole", "rds", mArn, map[string]interface{}{
						"name":       "awsRdsMonitoringRole",
						"region":     region,
						"instanceId": instID,
						"engine":     engine,
						"interval":   inst.MonitoringInterval,
					})
				}

				for _, ar := range inst.AssociatedRoles {
					roleArn := aws.ToString(ar.RoleArn)
					if roleArn == "" {
						continue
					}
					graph.AddEdge(out, "awsRdsInstanceRole", "rds", roleArn, map[string]interface{}{
						"name":        "awsRdsInstanceRole",
						"region":      region,
						"instanceId":  instID,
						"engine":      engine,
						"featureName": aws.ToString(ar.FeatureName),
						"status":      aws.ToString(ar.Status),
					})
				}
			}
		}

		clPager := rds.NewDescribeDBClustersPaginator(rdsconfig, &rds.DescribeDBClustersInput{})
		for clPager.HasMorePages() {
			page, err := clPager.NextPage(ctx)
			if err != nil {
				warn("rds", "DescribeDBClusters", region, err)
				break
			}
			for _, cl := range page.DBClusters {
				clusterID := aws.ToString(cl.DBClusterIdentifier)
				engine := aws.ToString(cl.Engine)

				// Cluster-level associated IAM roles
				for _, ar := range cl.AssociatedRoles {
					roleArn := aws.ToString(ar.RoleArn)
					if roleArn == "" {
						continue
					}
					graph.AddEdge(out, "awsRdsClusterRole", "rds", roleArn, map[string]interface{}{
						"name":        "awsRdsClusterRole",
						"region":      region,
						"clusterId":   clusterID,
						"engine":      engine,
						"featureName": aws.ToString(ar.FeatureName),
						"status":      aws.ToString(ar.Status),
					})
				}
			}
		}
	}
}
