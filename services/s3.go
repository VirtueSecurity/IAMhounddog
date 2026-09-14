package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/policies"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type s3ClientCache struct {
	cfg     aws.Config
	clients map[string]*s3.Client
}

func newS3ClientCache(cfg aws.Config) *s3ClientCache {
	return &s3ClientCache{cfg: cfg, clients: make(map[string]*s3.Client)}
}

func (c *s3ClientCache) get(region string) *s3.Client {
	if client, ok := c.clients[region]; ok {
		return client
	}

	client := s3.NewFromConfig(c.cfg, func(o *s3.Options) { o.Region = region })
	c.clients[region] = client
	return client
}

func bucketRegion(ctx context.Context, cache *s3ClientCache, b s3types.Bucket, fallback string) string {
	if region := aws.ToString(b.BucketRegion); region != "" {
		return region
	}

	loc, err := cache.get("us-east-1").GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: b.Name,
	})
	if err != nil {
		return fallback
	}

	switch loc.LocationConstraint {
	case "":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	default:
		return string(loc.LocationConstraint)
	}
}

func EnumerateS3Buckets(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, addedPrincipalNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "s3", []string{"AWSResource"}, map[string]interface{}{"name": "s3"})

	cache := newS3ClientCache(cfg)
	baseRegion := regions[0]

	buckets, err := cache.get(baseRegion).ListBuckets(ctx, &s3.ListBucketsInput{})
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
			bucketArn = fmt.Sprintf("arn:aws:s3:::%s", bucketName)
		}

		region := bucketRegion(ctx, cache, b, baseRegion)

		graph.AddNodeOnce(out, addedResourceNodes, bucketArn, []string{"AWSResource"}, map[string]interface{}{
			"name":   bucketName,
			"arn":    bucketArn,
			"region": region,
		})

		graph.AddEdge(out, "awsS3Bucket", "s3", bucketArn, map[string]interface{}{
			"name":   "awsS3Bucket",
			"bucket": bucketName,
			"region": region,
		})

		if strings.Contains(bucketName, "-tf-state") {
			graph.AddEdge(out, "awsCloudFormationS3Bucket", "cloudformation", bucketArn, map[string]interface{}{
				"name": "awsCloudFormationS3Bucket",
			})
		}

		policy, err := cache.get(region).GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil || policy.Policy == nil {
			continue
		}

		policies.ParseS3PolicyDoc(out, addedPrincipalNodes, bucketArn, aws.ToString(policy.Policy))
	}
}
