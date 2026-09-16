# Mock account harness

Runs the current tree and a baseline binary against the same fake AWS account,
then classifies every difference between the two graphs. Costs nothing and
touches no real account.

```
./testdata/mock/run.sh
```

First run creates a virtualenv under `.work/` and installs moto; later runs
reuse it. Results land in `out/` (git-ignored) and are **kept**, so both graphs
can be imported into BloodHound afterwards:

| file | |
|---|---|
| `out/baseline.json` | graph from the baseline binary |
| `out/current.json` | graph from the current tree |
| `out/report.txt` | the classified comparison |
| `out/*.log` | each run's console output, including warnings |

## Configuration

| variable | default |
|---|---|
| `BASELINE_BIN` | `~/go/bin/IAMhounddog` |
| `REGIONS` | `us-east-1,eu-west-1` |
| `MOTO_PORT` / `PROXY_PORT` | `5111` / `5110` |

Both binaries are given the same explicit `-regions` so that a change to the
built-in region list does not swamp the comparison. The baseline predates
`-output` and writes `./output.json`, so each run gets its own directory.

## How it fits together

```
IAMhounddog --AWS_ENDPOINT_URL--> proxy.py :5110 --> moto :5111
```

`aws-sdk-go-v2` honours `AWS_ENDPOINT_URL`, so neither binary needs modifying.

- **`seed.py`** builds the account: 12 groups, 42 users, 61 roles, 26 buckets,
  30 EC2 instances over 6 instance profiles, 240 ECS task definition revisions,
  150 CodeBuild projects, plus Lambda, EKS, RDS, Step Functions, CloudFormation
  and CodePipeline. It is deterministic; the same seed must produce the same
  graph or the comparison means nothing.

  It also plants specific parser cases, named `case-*` so they are greppable in
  the output: a single-object `Statement`, a `+` inside an ARN, a lowercase
  `iam:passrole`, a `NotAction` statement, a wildcard `PassRole` target, an
  explicit `Deny`, a trust open to `{"AWS": "*"}`, a bucket policy naming a role
  the account already enumerated, and one external account that appears in both
  a bucket policy and a trust policy.

- **`proxy.py`** does two things moto cannot. It repairs responses the Go SDK
  rejects (moto serialises CodePipeline timestamps as strings where the API
  models numbers, which otherwise drops the service entirely), and it enforces
  limits moto does not model, so the code that exists to handle them actually
  runs: `BatchGetProjects` rejects more than 100 names, and
  `--fail-nodegroups` makes `eks:ListNodegroups` return `AccessDenied`. It also
  implements `Get`/`SetIdentityPoolRoles`, which moto answers with a 500, so the
  Cognito collector has something to read. The seeder therefore takes two
  endpoints: moto for most calls, the proxy for those. Only those calls go
  through the proxy because routing S3 through it breaks moto's region
  inference on `CreateBucket`.

- **`compare.py`** groups the delta. A raw diff is useless here because most of
  the change is intended. Policy action edges are summarised in aggregate
  because thousands of them are expected to collapse; what matters is the line
  reporting **unique triples lost**, which must be zero. Structural edges, node
  ids, duplicate ids and per-property changes are listed in full.

## Reading the report

Every difference should be attributable. Anything that is not is a regression.

| where | expected |
|---|---|
| nodes only in current | S3 buckets: `ListBuckets` omits `BucketArn` for general purpose buckets, so the ARN has to be synthesised |
| `awsS3Bucket`, `s3*` edges | consequence of the above; bucket policies were never parsed before |
| policy action edges, huge drop | duplicates only, emitted once per attachment rather than once per principal |
| `awsEcsTask*Role` 240 -> 16 | described per family instead of per revision |
| `awsCodeBuildProjectRole` 30 -> 150 | a region with more than 100 projects used to fail the whole batch |
| `principal:aws:*` and `principal:aws:<arn>` | principals are namespaced so bucket and trust policies share one node |
| `*` -> role edge only in baseline | an any-kind node lookup used to match the wildcard *resource* node |
| `role/build deploy` vs `role/build+deploy` | `+` was decoded as a space |
| `trustPolicy` property | added on the `12dev` branch, not part of this work |

## The nodegroup case

```
./testdata/mock/run.sh --fail-nodegroups
```

`ListNodegroups` then returns `AccessDenied`. The baseline never exits: a failed
`NextPage` leaves the paginator untouched, so `HasMorePages` stays true and the
loop re-issues the same failing call forever. `run.sh` kills it after 120s and
says so. The current tree exits immediately having made one call.

## Non-determinism

moto mints stack ids and EC2 instance ids fresh on every seed, so those appear
in the graph and differ between runs even when nothing in the tool changed.
`compare.py` scrubs them before comparing properties. Everything else is
deterministic: two runs of an unchanged tree must produce a zero-delta report.
