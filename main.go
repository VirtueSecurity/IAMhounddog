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
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/VirtueSecurity/IAMhounddog/graph"
	"github.com/VirtueSecurity/IAMhounddog/principals"
	"github.com/VirtueSecurity/IAMhounddog/report"
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

func sendSignedRequest(url string, method string, uri string, keyid string, keytoken string, body []byte) error {
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
	req, err := http.NewRequest(method, url+uri, bodyReader)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "bhesignature "+keyid)
	req.Header.Set("RequestDate", requestDatetime)
	req.Header.Set("Signature", encodedHash)
	req.Header.Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}

	return nil
}

func main() {
	profile := flag.String("profile", "", "(Optional) AWS profile to use (uses env vars if not provided)")
	regionsFlag := flag.String("regions", "", "(Optional) Comma-separated list of AWS regions (tries all regions if not provided). Use -regions describe to use AWS described regions enabled for the account.")
	outputFlag := flag.String("output", "output.json", "(Optional) Output file name.")
	onlyRolesFlag := flag.Bool("onlyroles", false, "(Optional) Only enumerate IAM roles, users, groups, and trust relationships.")
	onlyServicesFlag := flag.Bool("onlyservices", false, "(Optional) Only enumerate service-attached roles.")
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
		if *urlFlag == "" || *keyIDFlag == "" || *keyTokenFlag == "" {
			fmt.Fprintln(os.Stderr, "-setup requires -url, -id and -token")
			os.Exit(1)
		}

		baseURL := strings.TrimRight(*urlFlag, "/")

		var queries []json.RawMessage
		if err := json.Unmarshal(queriesJSON, &queries); err != nil {
			fmt.Fprintln(os.Stderr, "unable to parse the bundled queries:", err)
			os.Exit(1)
		}

		fmt.Println("Importing custom nodes and queries")

		failed := 0

		if err := sendSignedRequest(baseURL, "POST", "/api/v2/custom-nodes", *keyIDFlag, *keyTokenFlag, typesJSON); err != nil {
			fmt.Fprintln(os.Stderr, "\t[!] custom nodes:", err)
			failed++
		}

		for i, query := range queries {
			if err := sendSignedRequest(baseURL, "POST", "/api/v2/saved-queries", *keyIDFlag, *keyTokenFlag, query); err != nil {
				fmt.Fprintf(os.Stderr, "\t[!] query %d of %d: %v\n", i+1, len(queries), err)
				failed++
			}
		}

		if failed > 0 {
			fmt.Fprintf(os.Stderr, "\n[!] %d of %d setup requests failed, BloodHound was not fully configured\n",
				failed, len(queries)+1)
			os.Exit(1)
		}

		fmt.Printf("Installed node icons and %d queries\n", len(queries))

		return
	}

	if *profile != "" {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(*profile))
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to load AWS configuration:", err)
		os.Exit(1)
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

			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] -regions describe failed, falling back to us-east-1: %v\n", err)
			} else if len(resp.Regions) == 0 {
				fmt.Fprintln(os.Stderr, "[!] -regions describe returned no regions, falling back to us-east-1")
			} else {
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
			"ap-east-1", "ap-east-2",
			"ap-south-1", "ap-south-2",
			"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
			"ap-southeast-5", "ap-southeast-7",
			"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
			"ca-central-1", "ca-west-1",
			"eu-central-1", "eu-central-2",
			"eu-west-1", "eu-west-2", "eu-west-3",
			"eu-north-1",
			"eu-south-1", "eu-south-2",
			"il-central-1",
			"me-central-1", "me-south-1",
			"mx-central-1",
			"sa-east-1",
		}
	}

	if len(regions) == 0 {
		regions = []string{
			"us-east-1",
		}
	}

	policyDocs := make(map[string]string)
	passRoleEdges := make(map[string]map[string]bool)

	out := graph.Output{Graph: graph.Graph{Nodes: []graph.Node{}, Edges: []graph.Edge{}}}

	if !*onlyServicesFlag {
		fmt.Println("Enumerating roles")
		principals.EnumerateRoles(ctx, client, &out, policyDocs, passRoleEdges)

		fmt.Println("Enumerating users")
		principals.EnumerateUsers(ctx, client, &out, policyDocs, passRoleEdges)

		fmt.Println("Enumerating groups")
		principals.EnumerateGroups(ctx, client, &out, policyDocs, passRoleEdges)

		// Need to do this here in case a role trusts a role and the role hasn't been created yet during the first loop
		fmt.Println("Enumerating trust relationships")
		principals.EnumerateTrusts(ctx, client, &out, passRoleEdges)
	}

	if !*onlyRolesFlag {
		fmt.Println("Enumerating services")

		fmt.Println("\tEnumerating lambdas")
		services.EnumerateLambdaExecutionRoles(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating ec2")
		services.EnumerateEC2InstanceRoles(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating rds")
		services.EnumerateRDSRoles(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating ecs")
		services.EnumerateECSTaskRoles(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating step functions")
		services.EnumerateStepFunctionRoles(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating eks")
		services.EnumerateEKSRoles(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating s3")
		services.EnumerateS3Buckets(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating cloudformation")
		services.EnumerateCloudFormationStackRoles(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating codebuild")
		services.EnumerateCodeBuildProjectRoles(ctx, cfg, &out, regions)

		fmt.Println("\tEnumerating codepipeline")
		services.EnumerateCodePipelineRoles(ctx, cfg, &out, regions)
	}

	report.Flush()

	fmt.Println("Creating graph")
	file, err := os.Create(*outputFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to create output file:", err)
		os.Exit(1)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "unable to write graph:", err)
		os.Exit(1)
	}
}
