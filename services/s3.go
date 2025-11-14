package services

import (
	"context"
	"strings"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func EnumerateS3Buckets(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, addedPrincipalNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "s3", []string{"AWSResource"}, map[string]interface{}{"name": "s3"})

	s3config := s3.NewFromConfig(cfg, func(o *s3.Options) { o.Region = regions[0] })

	buckets, err := s3config.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return
	}

	for _, b := range buckets.Buckets {
		bucketName := aws.ToString(b.Name)
		if bucketName == "" {
			continue
		}
		bucketArn := aws.ToString(b.BucketArn)
		if bucketArn == "" {
			continue
		}

		graph.AddNodeOnce(out, addedResourceNodes, bucketArn, []string{"AWSResource"}, map[string]interface{}{
			"name": bucketName,
			"arn":  bucketArn,
		})

		graph.AddEdge(out, "awsS3Bucket", "s3", bucketArn, map[string]interface{}{
			"name":   "awsS3Bucket",
			"bucket": bucketName,
		})

		if strings.Contains(bucketName, "-tf-state") {
			graph.AddEdge(out, "awsCloudFormationS3Bucket", "cloudformation", bucketArn, map[string]interface{}{
				"name": "awsCloudFormationS3Bucket",
			})
		}

		policy, err := s3config.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil || policy.Policy == nil {
			continue
		}

		policies.ParseS3PolicyDoc(out, addedPrincipalNodes, bucketArn, aws.ToString(policy.Policy))
	}
}
