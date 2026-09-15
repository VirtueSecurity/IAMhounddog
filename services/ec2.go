package services

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/VirtueSecurity/IAMhounddog/graph"
)

func instanceProfileNameFromArn(arn string) string {
	if arn == "" {
		return ""
	}
	parts := strings.Split(arn, "/")
	return parts[len(parts)-1]
}

func ec2NameTag(tags []ec2types.Tag) string {
	for _, t := range tags {
		if aws.ToString(t.Key) == "Name" {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

func instanceProfileRoles(ctx context.Context, client *iam.Client, cache map[string][]string, region, profileName string) []string {
	if roles, cached := cache[profileName]; cached {
		return roles
	}

	var roles []string

	resp, err := client.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	})
	if err != nil {
		warn("ec2", "GetInstanceProfile", region, err)
	} else if resp.InstanceProfile != nil {
		for _, r := range resp.InstanceProfile.Roles {
			if arn := aws.ToString(r.Arn); arn != "" {
				roles = append(roles, arn)
			}
		}
	}

	cache[profileName] = roles
	return roles
}

func EnumerateEC2InstanceRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "ec2", []string{"AWSResource"}, map[string]interface{}{"name": "ec2"})

	iamclient := iam.NewFromConfig(cfg)

	profileRoles := make(map[string][]string)

	for _, region := range regions {
		ec2config := ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = region })

		pager := ec2.NewDescribeInstancesPaginator(ec2config, &ec2.DescribeInstancesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				warn("ec2", "DescribeInstances", region, err)
				break
			}
			for _, res := range page.Reservations {
				for _, inst := range res.Instances {
					ip := inst.IamInstanceProfile
					if ip == nil || aws.ToString(ip.Arn) == "" {
						continue
					}

					profileName := instanceProfileNameFromArn(aws.ToString(ip.Arn))
					if profileName == "" {
						continue
					}
					instID := aws.ToString(inst.InstanceId)
					instName := ec2NameTag(inst.Tags)

					for _, roleArn := range instanceProfileRoles(ctx, iamclient, profileRoles, region, profileName) {
						graph.AddEdge(out, "awsEc2InstanceRole", "ec2", roleArn,
							map[string]interface{}{
								"name":        "awsEc2InstanceRole",
								"instanceId":  instID,
								"instance":    instName,
								"profileName": profileName,
							})
					}
				}
			}
		}
	}
}
