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

func EnumerateEC2InstanceRoles(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "ec2", []string{"AWSResource"}, map[string]interface{}{"name": "ec2"})

	iamclient := iam.NewFromConfig(cfg)

	for _, region := range regions {
		ec2config := ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = region })

		pager := ec2.NewDescribeInstancesPaginator(ec2config, &ec2.DescribeInstancesInput{})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
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
					profileResp, err := iamclient.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
						InstanceProfileName: aws.String(profileName),
					})
					if err != nil || profileResp.InstanceProfile == nil || len(profileResp.InstanceProfile.Roles) == 0 {
						continue
					}

					instID := aws.ToString(inst.InstanceId)
					instName := ec2NameTag(inst.Tags)

					for _, r := range profileResp.InstanceProfile.Roles {
						roleArn := aws.ToString(r.Arn)
						if roleArn == "" {
							continue
						}
						graph.AddEdge(out, "awsEc2InstanceRole", "ec2", roleArn,
							map[string]interface{}{
								"name":        "awsLambdaInstanceRole",
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
