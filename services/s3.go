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
		warn("s3", "GetBucketLocation", "", err)
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

type iacBucket struct {
	tool    string
	content string
	hub     string
	edge    string
	match   func(name string) bool
}

var iacBuckets = []iacBucket{
	{
		tool:    "terraform",
		content: "state",
		match: func(n string) bool {
			return strings.Contains(n, "tfstate") ||
				strings.Contains(n, "tf-state") ||
				strings.Contains(n, "terraform-state") ||
				strings.Contains(n, "terraformstate")
		},
	},
	{
		tool:    "cdk",
		content: "assets",
		match: func(n string) bool {
			return (strings.HasPrefix(n, "cdk-") && strings.Contains(n, "-assets-")) ||
				strings.Contains(n, "cdktoolkit-stagingbucket")
		},
	},
	{
		tool:    "cloudformation",
		content: "templates",
		hub:     "cloudformation",
		edge:    "awsCloudFormationTemplateBucket",
		match: func(n string) bool {
			return strings.HasPrefix(n, "cf-templates-")
		},
	},
}

func classifyIaCBucket(bucketName string) *iacBucket {
	lower := strings.ToLower(bucketName)

	for i := range iacBuckets {
		if iacBuckets[i].match(lower) {
			return &iacBuckets[i]
		}
	}

	return nil
}

func EnumerateS3Buckets(ctx context.Context, cfg aws.Config, out *graph.Output, addedResourceNodes map[string]bool, addedPrincipalNodes map[string]bool, regions []string) {
	graph.AddNodeOnce(out, addedResourceNodes, "s3", []string{"AWSResource"}, map[string]interface{}{"name": "s3"})

	cache := newS3ClientCache(cfg)
	baseRegion := regions[0]

	buckets, err := cache.get(baseRegion).ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		warn("s3", "ListBuckets", baseRegion, err)
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

		props := map[string]interface{}{
			"name":   bucketName,
			"arn":    bucketArn,
			"region": region,
		}

		iac := classifyIaCBucket(bucketName)
		if iac != nil {
			props["iacTool"] = iac.tool
			props["iacContent"] = iac.content
		}

		graph.AddNodeOnce(out, addedResourceNodes, bucketArn, []string{"AWSResource"}, props)

		graph.AddEdge(out, "awsS3Bucket", "s3", bucketArn, map[string]interface{}{
			"name":   "awsS3Bucket",
			"bucket": bucketName,
			"region": region,
		})

		if iac != nil && iac.hub != "" {
			graph.AddNodeOnce(out, addedResourceNodes, iac.hub, []string{"AWSResource"}, map[string]interface{}{
				"name": iac.hub,
			})

			graph.AddEdge(out, iac.edge, iac.hub, bucketArn, map[string]interface{}{
				"name":   iac.edge,
				"bucket": bucketName,
				"region": region,
			})
		}

		policy, err := cache.get(region).GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			// A bucket with no policy attached is normal, not a failure.
			if errorCode(err) != "NoSuchBucketPolicy" {
				warn("s3", "GetBucketPolicy", region, err)
			}
			continue
		}
		if policy.Policy == nil {
			continue
		}

		policies.ParseS3PolicyDoc(out, addedPrincipalNodes, bucketArn, aws.ToString(policy.Policy))
	}
}
