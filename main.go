package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/principals"
	"github.com/VirtueSecurity/IAMhounddog/services"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

//go:embed import/types.json
var typesJSON []byte

//go:embed import/queries.json
var queriesJSON []byte

func sendSignedRequest(url string, method string, uri string, keyid string, keytoken string, body []byte) {
	d := hmac.New(sha256.New, []byte(keytoken))
	d.Write([]byte(method + uri))
	opKey := d.Sum(nil)

	now := time.Now().Local()
	requestDatetime := now.Format(time.RFC3339)
	requestHour := now.Format("2006-01-02T15")

	d = hmac.New(sha256.New, opKey)
	d.Write([]byte(requestHour))
	dateKey := d.Sum(nil)

	d = hmac.New(sha256.New, dateKey)
	if len(body) > 0 {
		d.Write(body)
	}
	encodedHash := base64.StdEncoding.EncodeToString(d.Sum(nil))

	var bodyReader *bytes.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url+uri, bodyReader)

	req.Header.Set("Authorization", "bhesignature "+keyid)
	req.Header.Set("RequestDate", requestDatetime)
	req.Header.Set("Signature", encodedHash)
	req.Header.Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}

func main() {
	profile := flag.String("profile", "", "(Optional) AWS profile to use (uses env vars if not provided)")
	regionsFlag := flag.String("regions", "", "(Optional) Comma-separated list of AWS regions (tries all regions if not provided). Use -regions describe to use AWS described regions enabled for the account.")
	setupFlag := flag.Bool("setup", false, "(Optional) Enter setup mode. Used with the -url, -token, and -id parameters. Requires API key for BloodHound.")
	urlFlag := flag.String("url", "", "(Optional) Used with setup mode. Url for BloodHound instance. Use -url http://localhost:8080")
	keyIDFlag := flag.String("id", "", "(Optional) Used with setup mode. Key ID from create token.")
	keyTokenFlag := flag.String("token", "", "(Optional) Used with setup mode. Key token from create token.")
	flag.Parse()

	ctx := context.Background()
	var cfg aws.Config
	var err error

	// setup mode for tool
	if *setupFlag {
		fmt.Println("Importing custom nodes and queries")

		sendSignedRequest(*urlFlag, "POST", "/api/v2/custom-nodes", *keyIDFlag, *keyTokenFlag, typesJSON)

		var queries []json.RawMessage
		json.Unmarshal(queriesJSON, &queries)

		for _, query := range queries {
			sendSignedRequest(*urlFlag, "POST", "/api/v2/saved-queries", *keyIDFlag, *keyTokenFlag, query)
		}

		return
	}

	if *profile != "" {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(*profile))
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}
	if err != nil {
		panic(err)
	}

	// default region needed for IAM even though it is global
	if len(cfg.Region) == 0 {
		cfg.Region = "us-east-1"
	}

	client := iam.NewFromConfig(cfg)

	var regions []string
	if *regionsFlag != "" {
		if *regionsFlag == "describe" {
			ec2c := ec2.NewFromConfig(cfg)
			resp, err := ec2c.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
				AllRegions: aws.Bool(true),
				Filters: []ec2types.Filter{
					{
						Name:   aws.String("opt-in-status"),
						Values: []string{"opt-in-not-required", "opted-in"},
					},
				},
			})

			if err == nil && len(resp.Regions) > 0 {
				for _, r := range resp.Regions {
					if rn := aws.ToString(r.RegionName); rn != "" {
						regions = append(regions, rn)
					}
				}
			}
		} else {
			raw := strings.Split(*regionsFlag, ",")
			for _, r := range raw {
				trimmed := strings.TrimSpace(r)
				if trimmed != "" {
					regions = append(regions, trimmed)
				}
			}
		}
	} else {
		regions = []string{
			"us-east-1", "us-east-2", "us-west-1", "us-west-2",
			"af-south-1",
			"ap-east-1", "ap-south-1", "ap-south-2",
			"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
			"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
			"ca-central-1",
			"eu-central-1", "eu-central-2",
			"eu-west-1", "eu-west-2", "eu-west-3",
			"eu-north-1",
			"eu-south-1", "eu-south-2",
			"me-central-1", "me-south-1",
			"sa-east-1",
		}
	}

	if len(regions) == 0 {
		regions = []string{
			"us-east-1",
		}
	}

	addedPolicyNodes := make(map[string]bool)
	addedResourceNodes := make(map[string]bool)
	addedPrincipalNodes := make(map[string]bool)
	passRoleEdges := make(map[string]map[string]bool)

	out := graph.Output{Graph: graph.Graph{Nodes: []graph.Node{}, Edges: []graph.Edge{}}}

	fmt.Println("Enumerating roles")
	principals.EnumerateRoles(ctx, client, &out, addedPolicyNodes, addedResourceNodes, passRoleEdges)

	fmt.Println("Enumerating users")
	principals.EnumerateUsers(ctx, client, &out, addedPolicyNodes, addedResourceNodes, passRoleEdges)

	fmt.Println("Enumerating groups")
	principals.EnumerateGroups(ctx, client, &out, addedPolicyNodes, addedResourceNodes, passRoleEdges)

	// Need to do this here in case a role trusts a role and the role hasn't been created yet during the first loop
	fmt.Println("Enumerating trust relationships")
	principals.EnumerateTrusts(ctx, client, &out, addedPrincipalNodes, passRoleEdges)

	fmt.Println("Enumerating services")

	fmt.Println("\tEnumerating lambdas")
	services.EnumerateLambdaExecutionRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("\tEnumerating ec2")
	services.EnumerateEC2InstanceRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("\tEnumerating rds")
	services.EnumerateRDSRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("\tEnumerating ecs")
	services.EnumerateECSTaskRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("\tEnumerating step functions")
	services.EnumerateStepFunctionRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("\tEnumerating eks")
	services.EnumerateEKSRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("\tEnumerating s3")
	services.EnumerateS3Buckets(ctx, cfg, &out, addedResourceNodes, addedPrincipalNodes, regions)

	fmt.Println("\tEnumerating cloudformation")
	services.EnumerateCloudFormationStackRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("\tEnumerating codebuild")
	services.EnumerateCodeBuildProjectRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("\tEnumerating codepipeline")
	services.EnumerateCodePipelineRoles(ctx, cfg, &out, addedResourceNodes, regions)

	fmt.Println("Creating graph")
	file, err := os.Create("output.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		panic(err)
	}
}
