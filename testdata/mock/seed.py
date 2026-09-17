"""Seed a moto server with a mid-size AWS account.

Deterministic on purpose: the same seed must produce the same graph every run,
or the baseline/current comparison is meaningless.
"""

import json
import sys

import boto3
from botocore.config import Config

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5111"

# moto returns a 500 for the identity-pool role APIs, so those calls go to the
# proxy, which implements them. Everything else talks to moto directly:
# proxying S3 breaks moto's region inference on CreateBucket.
PROXY_ENDPOINT = sys.argv[2] if len(sys.argv) > 2 else ENDPOINT
REGIONS = ["us-east-1", "eu-west-1"]
ACCOUNT = "123456789012"
EXTERNAL = "arn:aws:iam::999988887777:root"

CFG = Config(retries={"max_attempts": 1}, max_pool_connections=50)


def client(service, region="us-east-1", endpoint=None):
    return boto3.client(
        service,
        endpoint_url=endpoint or ENDPOINT,
        region_name=region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=CFG,
    )


iam = client("iam")


def doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def allow(actions, resources="*", **extra):
    s = {"Effect": "Allow", "Action": actions, "Resource": resources}
    s.update(extra)
    return s


def service_trust(*services):
    principals = [s + ".amazonaws.com" for s in services]
    # AWS emits a bare string for a single service principal, a list for several.
    return doc({
        "Effect": "Allow",
        "Principal": {"Service": principals[0] if len(principals) == 1 else principals},
        "Action": "sts:AssumeRole",
    })


# ---------------------------------------------------------------- IAM policies

CUSTOMER_POLICIES = {
    "app-read": allow(["s3:GetObject", "s3:ListBucket", "dynamodb:GetItem"]),
    "app-write": allow(["s3:PutObject", "s3:DeleteObject"]),
    "secrets-read": allow(["secretsmanager:GetSecretValue", "kms:Decrypt"]),
    "lambda-deploy": allow(["lambda:UpdateFunctionCode", "lambda:CreateFunction", "iam:PassRole"]),
    "ecs-deploy": allow(["ecs:RegisterTaskDefinition", "ecs:UpdateService", "iam:PassRole"]),
    "ec2-ops": allow(["ec2:RunInstances", "ec2:TerminateInstances", "ec2:DescribeInstances"]),
    "iam-audit": allow(["iam:Get*", "iam:List*"]),
    "cfn-deploy": allow(["cloudformation:CreateStack", "cloudformation:UpdateStack", "iam:PassRole"]),
    "eks-admin": allow(["eks:*"]),
    "rds-ops": allow(["rds:DescribeDBInstances", "rds:ModifyDBInstance"]),
    "codebuild-run": allow(["codebuild:StartBuild", "codebuild:BatchGetProjects"]),
    "sfn-exec": allow(["states:StartExecution", "states:DescribeExecution"]),
    "logs-read": allow(["logs:GetLogEvents", "logs:FilterLogEvents"]),
    "sqs-consume": allow(["sqs:ReceiveMessage", "sqs:DeleteMessage"]),
    "sns-publish": allow(["sns:Publish"]),
    "glue-job-deploy": allow(["glue:UpdateJob", "glue:CreateJob", "glue:StartJobRun",
                              "glue:CreateDevEndpoint", "glue:GetJobs"]),
}

# Cases that specifically exercise parser behaviour. Names are referenced by
# the comparison report, so keep them stable.
EDGE_CASE_POLICIES = {
    # Statement as a single object rather than an array.
    "case-single-statement": json.dumps({
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"},
    }),
    # '+' inside an ARN, in the normal array form.
    "case-plus-in-arn": doc(
        allow("iam:PassRole", "arn:aws:iam::%s:role/build+deploy" % ACCOUNT)
    ),
    # Lowercase action: IAM matches case-insensitively, the tool does not.
    "case-lowercase-passrole": doc(
        allow("iam:passrole", "arn:aws:iam::%s:role/svc-lambda-exec" % ACCOUNT)
    ),
    # NotAction is invisible to the parser.
    "case-notaction": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}],
    }),
    # Wildcard PassRole target.
    "case-wildcard-passrole": doc(allow("iam:PassRole", "*")),
    # Deny should never produce edges.
    "case-explicit-deny": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
    }),
}

policy_arns = {}
for name, body in {**CUSTOMER_POLICIES, **EDGE_CASE_POLICIES}.items():
    body = body if isinstance(body, str) else doc(body)
    policy_arns[name] = iam.create_policy(
        PolicyName=name, PolicyDocument=body
    )["Policy"]["Arn"]

AWS_MANAGED = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/ReadOnlyAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/AWSLambda_FullAccess",
]

print("policies:", len(policy_arns), "customer +", len(AWS_MANAGED), "aws-managed")


# ------------------------------------------------------------ groups and users

GROUPS = {
    "Developers": ["app-read", "app-write", "lambda-deploy"],
    "SeniorDevelopers": ["app-read", "app-write", "ecs-deploy", "secrets-read"],
    "Operations": ["ec2-ops", "rds-ops", "logs-read"],
    "SRE": ["ec2-ops", "eks-admin", "cfn-deploy"],
    "Security": ["iam-audit", "logs-read"],
    "DataEngineering": ["app-read", "sqs-consume", "sfn-exec", "glue-job-deploy"],
    "QA": ["app-read", "logs-read"],
    "Support": ["logs-read"],
    "Contractors": ["app-read"],
    "BuildEngineers": ["codebuild-run", "cfn-deploy"],
    "Finance": ["logs-read"],
    "Admins": [],
}

for group, policies in GROUPS.items():
    iam.create_group(GroupName=group)
    for p in policies:
        iam.attach_group_policy(GroupName=group, PolicyArn=policy_arns[p])

iam.attach_group_policy(GroupName="Admins", PolicyArn=AWS_MANAGED[0])
iam.attach_group_policy(GroupName="Security", PolicyArn=AWS_MANAGED[3])
iam.put_group_policy(
    GroupName="SeniorDevelopers",
    PolicyName="inline-senior-escalate",
    PolicyDocument=doc(allow(["iam:PutRolePolicy", "iam:AttachRolePolicy"])),
)

USER_GROUPS = [
    ("Developers", 12), ("SeniorDevelopers", 4), ("Operations", 5), ("SRE", 3),
    ("Security", 3), ("DataEngineering", 4), ("QA", 3), ("Support", 2),
    ("Contractors", 2), ("BuildEngineers", 2), ("Admins", 2),
]

users = []
n = 0
for group, count in USER_GROUPS:
    for i in range(count):
        n += 1
        name = "%s%02d" % (group.lower()[:6], i + 1)
        iam.create_user(UserName=name)
        iam.add_user_to_group(GroupName=group, UserName=name)
        users.append(name)

# A few users carry permissions directly as well as through their group.
iam.attach_user_policy(UserName=users[0], PolicyArn=policy_arns["secrets-read"])
iam.attach_user_policy(UserName=users[1], PolicyArn=AWS_MANAGED[1])
iam.put_user_policy(
    UserName=users[2],
    PolicyName="inline-user-passrole",
    PolicyDocument=doc(allow("iam:PassRole", "arn:aws:iam::%s:role/svc-ec2-app" % ACCOUNT)),
)
iam.attach_user_policy(UserName=users[3], PolicyArn=policy_arns["case-plus-in-arn"])
iam.attach_user_policy(UserName=users[4], PolicyArn=policy_arns["case-single-statement"])
iam.attach_user_policy(UserName=users[5], PolicyArn=policy_arns["case-lowercase-passrole"])
iam.attach_user_policy(UserName=users[6], PolicyArn=policy_arns["case-notaction"])
iam.attach_user_policy(UserName=users[7], PolicyArn=policy_arns["case-wildcard-passrole"])
iam.attach_user_policy(UserName=users[8], PolicyArn=policy_arns["case-explicit-deny"])

print("groups:", len(GROUPS), " users:", len(users))


# ----------------------------------------------------------------------- roles

def make_role(name, trust, managed=(), inline=None):
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)
    for p in managed:
        arn = p if p.startswith("arn:") else policy_arns[p]
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
    if inline:
        iam.put_role_policy(RoleName=name, PolicyName=inline[0], PolicyDocument=inline[1])
    return "arn:aws:iam::%s:role/%s" % (ACCOUNT, name)


roles = {}

# Service roles, referenced later by the resources that use them.
SERVICE_ROLES = [
    ("svc-lambda-exec", ["lambda"], ["app-read", "secrets-read"]),
    ("svc-lambda-admin", ["lambda"], [AWS_MANAGED[0]]),
    ("svc-lambda-etl", ["lambda"], ["app-read", "app-write", "sqs-consume"]),
    ("svc-ec2-app", ["ec2"], ["app-read", "logs-read"]),
    ("svc-ec2-build", ["ec2"], ["codebuild-run", "app-write"]),
    ("svc-ec2-bastion", ["ec2"], [AWS_MANAGED[1]]),
    ("svc-ecs-task", ["ecs-tasks"], ["app-read", "secrets-read"]),
    ("svc-ecs-exec", ["ecs-tasks"], ["logs-read"]),
    ("svc-ecs-privileged", ["ecs-tasks"], [AWS_MANAGED[2]]),
    ("svc-eks-cluster", ["eks"], ["eks-admin"]),
    ("svc-eks-node", ["ec2"], ["app-read", "logs-read"]),
    ("svc-rds-monitor", ["monitoring.rds"], ["rds-ops"]),
    ("svc-rds-s3import", ["rds"], ["app-read"]),
    ("svc-sfn-exec", ["states"], ["lambda-deploy", "sfn-exec"]),
    ("svc-cfn-deploy", ["cloudformation"], [AWS_MANAGED[0]]),
    ("svc-codebuild", ["codebuild"], ["app-write", "logs-read", "secrets-read"]),
    ("svc-codepipeline", ["codepipeline"], ["cfn-deploy", "codebuild-run"]),
]

for name, services, managed in SERVICE_ROLES:
    roles[name] = make_role(name, service_trust(*services), managed)

# Human-assumable roles, reachable from users and groups.
for name, managed in [
    ("OrganizationAccountAccessRole", [AWS_MANAGED[0]]),
    ("ReadOnlyAuditor", [AWS_MANAGED[3]]),
    ("IncidentResponder", [AWS_MANAGED[1], "secrets-read"]),
    ("DeploymentRole", ["cfn-deploy", "lambda-deploy", "ecs-deploy"]),
    ("DataScientist", ["app-read", "sfn-exec"]),
]:
    roles[name] = make_role(
        name,
        doc({"Effect": "Allow",
             "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT},
             "Action": "sts:AssumeRole"}),
        managed,
    )

# Cross-account trusts, including the same external account that also appears
# in a bucket policy below. Both must resolve to one shared principal node.
for i in range(6):
    name = "CrossAccount%02d" % (i + 1)
    roles[name] = make_role(
        name,
        doc({"Effect": "Allow", "Principal": {"AWS": EXTERNAL},
             "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"sts:ExternalId": "shared-secret-%d" % i}}}),
        ["app-read"],
    )

# Federated trusts.
roles["SAMLFederated"] = make_role(
    "SAMLFederated",
    doc({"Effect": "Allow",
         "Principal": {"Federated": "arn:aws:iam::%s:saml-provider/Okta" % ACCOUNT},
         "Action": "sts:AssumeRoleWithSAML",
         "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}}),
    ["app-read"],
)
roles["OIDCGitHubActions"] = make_role(
    "OIDCGitHubActions",
    doc({"Effect": "Allow",
         "Principal": {"Federated": "arn:aws:iam::%s:oidc-provider/token.actions.githubusercontent.com" % ACCOUNT},
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*"}}}),
    ["cfn-deploy", "lambda-deploy"],
)

# Trust open to any principal.
roles["WildcardTrust"] = make_role(
    "WildcardTrust",
    doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}),
    [AWS_MANAGED[2]],
)

# In-account role-to-role trusts carrying conditions. The condition on these is
# what the baseline dropped.
for src, dst in [("svc-ecs-task", "EscalationTargetA"), ("svc-lambda-exec", "EscalationTargetB")]:
    roles[dst] = make_role(
        dst,
        doc({"Effect": "Allow", "Principal": {"AWS": roles[src]},
             "Action": "sts:AssumeRole",
             "Condition": {"StringLike": {"sts:RoleSessionName": "deploy-*"}}}),
        [AWS_MANAGED[0]],
    )

# Filler roles so the account has a realistic population.
for i in range(28):
    name = "app-role-%02d" % (i + 1)
    managed = ["app-read"]
    if i % 5 == 0:
        managed.append(AWS_MANAGED[1])       # ReadOnlyAccess, 2914 actions
    if i % 9 == 0:
        managed.append(AWS_MANAGED[0])       # AdministratorAccess
    inline = None
    if i % 7 == 0:
        inline = ("inline-passrole",
                  doc(allow("iam:PassRole", "arn:aws:iam::%s:role/svc-lambda-exec" % ACCOUNT)))
    roles[name] = make_role(name, service_trust("ec2"), managed, inline)

print("roles:", len(roles))


# ------------------------------------------------------------------------- S3

BUCKETS = [
    ("acme-tfstate", "us-east-1"),
    ("acme-prod-tf-state", "eu-west-1"),
    ("terraform-state-%s" % ACCOUNT, "us-east-1"),
    ("cdk-hnb659fds-assets-%s-us-east-1" % ACCOUNT, "us-east-1"),
    ("cdktoolkit-stagingbucket-a1b2c3d4e5", "us-east-1"),
    ("cf-templates-1q2w3e4r5t6y-us-east-1", "us-east-1"),
    ("acme-app-data", "us-east-1"),
    ("acme-app-logs", "eu-west-1"),
    ("acme-backups", "eu-west-1"),
    ("acme-customer-assets-bucket", "us-east-1"),
    ("acme-statement-archive", "us-east-1"),
    ("acme-public-web", "us-east-1"),
]
for i in range(14):
    BUCKETS.append(("acme-data-%02d" % (i + 1), REGIONS[i % 2]))

for name, region in BUCKETS:
    s3 = client("s3", region)
    kw = {"Bucket": name}
    if region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kw)

s3e = client("s3")

# Principal "*" on a bucket: must not collide with the wildcard resource node.
s3e.put_bucket_policy(Bucket="acme-public-web", Policy=doc({
    "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::acme-public-web/*"}))

# Bucket policy naming a role this account already enumerated: the edge must
# start from the existing role node, not a duplicate principal node.
s3e.put_bucket_policy(Bucket="acme-app-data", Policy=doc({
    "Effect": "Allow", "Principal": {"AWS": roles["svc-lambda-exec"]},
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::acme-app-data/*"}))

# The same external account that several roles already trust.
s3e.put_bucket_policy(Bucket="acme-backups", Policy=doc({
    "Effect": "Allow", "Principal": {"AWS": EXTERNAL},
    "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::acme-backups"}))

s3e.put_bucket_policy(Bucket="acme-tfstate", Policy=doc({
    "Effect": "Allow", "Principal": {"AWS": roles["svc-codepipeline"]},
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::acme-tfstate/*"}))

print("buckets:", len(BUCKETS))


# ------------------------------------------------------------- EC2 + profiles

PROFILES = ["svc-ec2-app", "svc-ec2-build", "svc-ec2-bastion",
            "app-role-01", "app-role-05", "app-role-10"]
for r in PROFILES:
    iam.create_instance_profile(InstanceProfileName=r)
    iam.add_role_to_instance_profile(InstanceProfileName=r, RoleName=r)

instances = 0
for region in REGIONS:
    ec2 = client("ec2", region)
    for i in range(15):
        profile = PROFILES[i % len(PROFILES)]
        ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1,
            IamInstanceProfile={"Name": profile},
            TagSpecifications=[{"ResourceType": "instance", "Tags": [
                {"Key": "Name", "Value": "%s-host-%02d" % (region, i + 1)}]}],
        )
        instances += 1
print("ec2 instances:", instances, "across", len(PROFILES), "instance profiles")


# --------------------------------------------------------------------- Lambda

lambdas = 0
for region in REGIONS:
    lam = client("lambda", region)
    for i in range(12):
        role = roles[["svc-lambda-exec", "svc-lambda-admin", "svc-lambda-etl"][i % 3]]
        lam.create_function(
            FunctionName="%s-fn-%02d" % (region, i + 1),
            Runtime="python3.12", Role=role, Handler="index.handler",
            Code={"ZipFile": b"x"}, PackageType="Zip",
        )
        lambdas += 1
print("lambda functions:", lambdas)


# ------------------------------------------------------------------------ ECS

FAMILIES = ["web", "api", "worker", "batch", "scheduler", "ingest", "report", "sidecar"]
revisions = 0
for region in REGIONS:
    ecs = client("ecs", region)
    ecs.create_cluster(clusterName="primary")
    for f in FAMILIES:
        for rev in range(15):
            ecs.register_task_definition(
                family=f,
                taskRoleArn=roles["svc-ecs-privileged" if f == "batch" else "svc-ecs-task"],
                executionRoleArn=roles["svc-ecs-exec"],
                networkMode="awsvpc", cpu="256", memory="512",
                containerDefinitions=[{"name": f, "image": "acme/%s:v%d" % (f, rev),
                                       "memory": 512, "essential": True}],
            )
            revisions += 1
print("ecs task definitions:", revisions, "across", len(FAMILIES) * len(REGIONS), "families")


# ------------------------------------------------------------- Step Functions

sfns = 0
for region in REGIONS:
    sfn = client("stepfunctions", region)
    for i in range(4):
        sfn.create_state_machine(
            name="workflow-%02d" % (i + 1),
            definition=json.dumps({"StartAt": "a", "States": {"a": {"Type": "Pass", "End": True}}}),
            roleArn=roles["svc-sfn-exec"],
        )
        sfns += 1
print("state machines:", sfns)


# ------------------------------------------------------------------------ EKS

eks_n = 0
for region in REGIONS:
    eks = client("eks", region)
    for i in range(1):
        name = "%s-cluster-%02d" % (region, i + 1)
        eks.create_cluster(
            name=name, roleArn=roles["svc-eks-cluster"],
            resourcesVpcConfig={"subnetIds": ["subnet-1111", "subnet-2222"]},
        )
        for ng in range(2):
            eks.create_nodegroup(
                clusterName=name, nodegroupName="ng-%02d" % (ng + 1),
                nodeRole=roles["svc-eks-node"],
                subnets=["subnet-1111", "subnet-2222"],
            )
        eks_n += 1
print("eks clusters:", eks_n)


# ------------------------------------------------------------------------ RDS

rds_n = 0
for region in REGIONS:
    rds = client("rds", region)
    for i in range(2):
        rds.create_db_instance(
            DBInstanceIdentifier="db-%s-%02d" % (region, i + 1),
            DBInstanceClass="db.t3.micro", Engine="postgres",
            MasterUsername="admin", MasterUserPassword="Password123",
            MonitoringRoleArn=roles["svc-rds-monitor"], MonitoringInterval=60,
        )
        rds_n += 1
    rds.create_db_cluster(
        DBClusterIdentifier="cluster-%s" % region, Engine="aurora-postgresql",
        MasterUsername="admin", MasterUserPassword="Password123",
    )
print("rds instances:", rds_n, "+ clusters:", len(REGIONS))


# -------------------------------------------------------------- CloudFormation

TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "Data": {"Type": "AWS::S3::Bucket",
                 "Properties": {"BucketName": "REPLACE"}},
    },
})

stacks = 0
for region in REGIONS:
    cfn = client("cloudformation", region)
    for i in range(3):
        bucket = "acme-stack-%s-%02d" % (region, i + 1)
        cfn.create_stack(
            StackName="stack-%s-%02d" % (region, i + 1),
            TemplateBody=TEMPLATE.replace("REPLACE", bucket),
            RoleARN=roles["svc-cfn-deploy"],
        )
        stacks += 1
print("cloudformation stacks:", stacks)


# ------------------------------------------------------------------ CodeBuild

# Deliberately over 100 in one region: BatchGetProjects caps at 100 names.
projects = 0
for region, count in zip(REGIONS, [120, 30]):
    cb = client("codebuild", region)
    for i in range(count):
        cb.create_project(
            name="build-%s-%03d" % (region, i + 1),
            source={"type": "S3", "location": "acme-app-data/src.zip",
                    "buildspec": "version: 0.2"},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={"type": "LINUX_CONTAINER", "image": "aws/codebuild/standard:7.0",
                         "computeType": "BUILD_GENERAL1_SMALL"},
            serviceRole=roles["svc-codebuild"],
        )
        projects += 1
print("codebuild projects:", projects)


# --------------------------------------------------------------- CodePipeline

pipelines = 0
for region in REGIONS:
    cp = client("codepipeline", region)
    for i in range(4):
        cp.create_pipeline(pipeline={
            "name": "pipeline-%s-%02d" % (region, i + 1),
            "roleArn": roles["svc-codepipeline"],
            "artifactStore": {"type": "S3", "location": "acme-tfstate"},
            "stages": [
                {"name": "Source", "actions": [{
                    "name": "Source",
                    "actionTypeId": {"category": "Source", "owner": "AWS",
                                     "provider": "S3", "version": "1"},
                    "configuration": {"S3Bucket": "acme-app-data", "S3ObjectKey": "src.zip"},
                    "outputArtifacts": [{"name": "src"}]}]},
                {"name": "Build", "actions": [{
                    "name": "Build",
                    "actionTypeId": {"category": "Build", "owner": "AWS",
                                     "provider": "CodeBuild", "version": "1"},
                    "configuration": {"ProjectName": "build-%s-001" % region},
                    "inputArtifacts": [{"name": "src"}]}]},
            ],
        })
        pipelines += 1
print("codepipelines:", pipelines)

print("\nseed complete")


# ---------------------------------------------------------------- Cognito

# Roles assumed through an identity pool, with the trust policy Cognito
# actually writes. The third deliberately omits the amr condition, which lets an
# unauthenticated identity assume the authenticated role.
def cognito_trust(pool_placeholder, amr=None):
    cond = {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_placeholder}}
    if amr:
        cond["ForAnyValue:StringLike"] = {"cognito-identity.amazonaws.com:amr": amr}
    return doc({
        "Effect": "Allow",
        "Principal": {"Federated": "cognito-identity.amazonaws.com"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": cond,
    })


ci = client("cognito-identity")
ci_roles = client("cognito-identity", endpoint=PROXY_ENDPOINT)
idp = client("cognito-idp")

user_pool = idp.create_user_pool(PoolName="acme-users")["UserPool"]
user_pool_client = idp.create_user_pool_client(
    UserPoolId=user_pool["Id"], ClientName="acme-web")["UserPoolClient"]

POOLS = [
    # Guest access on: anyone with the pool id gets the unauthenticated role.
    ("acme-guest-pool", True, "CognitoGuest", "CognitoUser"),
    ("acme-app-pool", False, None, "CognitoAppUser"),
]

cognito_pools = {}
for name, allow_unauth, unauth_role, auth_role in POOLS:
    pool = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        CognitoIdentityProviders=[{
            "ProviderName": "cognito-idp.us-east-1.amazonaws.com/%s" % user_pool["Id"],
            "ClientId": user_pool_client["ClientId"],
        }],
    )
    pid = pool["IdentityPoolId"]
    cognito_pools[name] = pid

    roles = {}
    if auth_role:
        roles["authenticated"] = make_role(
            auth_role, cognito_trust(pid, "authenticated"), ["app-read", "secrets-read"])
    if unauth_role:
        # No amr condition: an unauthenticated identity can take this too.
        roles["unauthenticated"] = make_role(
            unauth_role, cognito_trust(pid), [AWS_MANAGED[1]])

    mapped = make_role("CognitoMapped-%s" % name, cognito_trust(pid, "authenticated"),
                       [AWS_MANAGED[0]])

    ci_roles.set_identity_pool_roles(
        IdentityPoolId=pid,
        Roles=roles,
        RoleMappings={
            "cognito-idp.us-east-1.amazonaws.com/%s:%s" % (user_pool["Id"], user_pool_client["ClientId"]): {
                "Type": "Rules",
                "AmbiguousRoleResolution": "Deny",
                "RulesConfiguration": {"Rules": [{
                    "Claim": "custom:role", "MatchType": "Equals",
                    "Value": "admin", "RoleARN": mapped,
                }]},
            },
        },
    )

print("cognito identity pools:", len(cognito_pools), "+ 1 user pool")


# ------------------------------------------------------- Bedrock AgentCore

# An agent takes its instructions from input, so an over-permissioned execution
# role here is reachable by prompt injection rather than needing a code
# execution bug. The first runtime deliberately runs as an admin.
ac = client("bedrock-agentcore-control")

agentcore_trust = service_trust("bedrock-agentcore")

AGENT_ROLES = {
    "AgentCoreRuntimeAdmin": [AWS_MANAGED[0]],
    "AgentCoreRuntimeScoped": ["app-read", "secrets-read"],
    "AgentCoreGatewayRole": ["lambda-deploy"],
}
for name, managed in AGENT_ROLES.items():
    roles[name] = make_role(name, agentcore_trust, managed)

RUNTIMES = [("acme_support_agent", "AgentCoreRuntimeAdmin"),
            ("acme_report_agent", "AgentCoreRuntimeScoped")]

agentcore_runtimes = 0
for name, role in RUNTIMES:
    ac.create_agent_runtime(
        agentRuntimeName=name,
        roleArn=roles[role],
        agentRuntimeArtifact={"containerConfiguration": {
            "containerUri": "%s.dkr.ecr.us-east-1.amazonaws.com/agents:latest" % ACCOUNT}},
        networkConfiguration={"networkMode": "PUBLIC"},
    )
    agentcore_runtimes += 1

ac.create_gateway(
    name="acme-tool-gateway",
    roleArn=roles["AgentCoreGatewayRole"],
    protocolType="MCP",
    authorizerType="CUSTOM_JWT",
    authorizerConfiguration={"customJWTAuthorizer": {
        "discoveryUrl": "https://example.com/.well-known/openid-configuration",
        "allowedClients": ["acme-client"]}},
)

# moto returns a 500 for CreateCodeInterpreter and CreateBrowser, so those two
# collector paths are not exercised here.
# moto 500s on these two, so they are created against the proxy, which
# implements them.
ac_proxy = client("bedrock-agentcore-control", endpoint=PROXY_ENDPOINT)
ac_proxy.create_code_interpreter(
    name="acme_ci", executionRoleArn=roles["AgentCoreRuntimeScoped"],
    networkConfiguration={"networkMode": "PUBLIC"})
ac_proxy.create_browser(
    name="acme_browser", executionRoleArn=roles["AgentCoreRuntimeAdmin"],
    networkConfiguration={"networkMode": "PUBLIC"})

print("agentcore runtimes:", agentcore_runtimes, "+ 1 gateway, 1 code interpreter, 1 browser")


# ------------------------------------------------------------------ SageMaker

# A notebook's role is reachable by anyone holding
# sagemaker:CreatePresignedNotebookInstanceUrl, with no PassRole and no code
# execution bug, so the first notebook deliberately runs as an admin.
sm = client("sagemaker")

sagemaker_trust = service_trust("sagemaker")

SAGEMAKER_ROLES = {
    "SageMakerNotebookAdmin": [AWS_MANAGED[0]],
    "SageMakerNotebookScoped": ["app-read"],
    "SageMakerStudioExec": ["app-read", "secrets-read"],
    "SageMakerModelExec": ["app-read"],
    "SageMakerPipelineExec": ["app-read", "app-write"],
}
for name, managed in SAGEMAKER_ROLES.items():
    roles[name] = make_role(name, sagemaker_trust, managed)

for nb, role in [("acme-research-nb", "SageMakerNotebookAdmin"),
                 ("acme-reporting-nb", "SageMakerNotebookScoped")]:
    sm.create_notebook_instance(
        NotebookInstanceName=nb, InstanceType="ml.t3.medium", RoleArn=roles[role])

sm.create_domain(
    DomainName="acme-studio", AuthMode="IAM",
    DefaultUserSettings={"ExecutionRole": roles["SageMakerStudioExec"]},
    SubnetIds=["subnet-1111"], VpcId="vpc-1111")

for m in ["acme-fraud-model", "acme-churn-model"]:
    sm.create_model(
        ModelName=m, ExecutionRoleArn=roles["SageMakerModelExec"],
        PrimaryContainer={"Image": "%s.dkr.ecr.us-east-1.amazonaws.com/models:1" % ACCOUNT})

sm.create_pipeline(
    PipelineName="acme-training-pipeline", RoleArn=roles["SageMakerPipelineExec"],
    PipelineDefinition='{"Version":"2020-12-01","Steps":[]}')

# A user profile overrides the domain default, and moto 500s on these too.
domain_id = sm.list_domains()["Domains"][0]["DomainId"]
sm_proxy = client("sagemaker", endpoint=PROXY_ENDPOINT)
sm_proxy.create_user_profile(
    DomainId=domain_id, UserProfileName="analyst",
    UserSettings={"ExecutionRole": roles["SageMakerNotebookAdmin"]})

print("sagemaker: 2 notebooks, 1 studio domain, 1 user profile, 2 models, 1 pipeline")


# ----------------------------------------------------------------------- Glue

# glue:UpdateJob rewrites the script an existing job runs, so the job's role is
# reachable without iam:PassRole. Glue also accepts either a role name or an
# ARN, so one job here is configured with a bare name to exercise resolution.
gl = client("glue")

glue_trust = service_trust("glue")

GLUE_ROLES = {
    "GlueJobRole": [AWS_MANAGED[0]],
    "GlueCrawlerRole": ["app-read"],
    "GlueDevEndpointRole": ["app-read", "secrets-read"],
}
for name, managed in GLUE_ROLES.items():
    roles[name] = make_role(name, glue_trust, managed)

gl.create_database(DatabaseInput={"Name": "acme_lake"})

# Role given as a full ARN.
gl.create_job(Name="acme-etl", Role=roles["GlueJobRole"],
              Command={"Name": "glueetl", "ScriptLocation": "s3://acme-app-data/etl.py"})

# Role given as a bare name that matches an enumerated role: must resolve.
gl.create_job(Name="acme-nightly", Role="GlueJobRole",
              Command={"Name": "glueetl", "ScriptLocation": "s3://acme-app-data/nightly.py"})

# Role given as a bare name with no matching role: must land on a stub.
gl.create_job(Name="acme-orphan", Role="GlueDeletedRole",
              Command={"Name": "glueetl", "ScriptLocation": "s3://acme-app-data/orphan.py"})

gl.create_crawler(Name="acme-crawler", Role=roles["GlueCrawlerRole"],
                  DatabaseName="acme_lake",
                  Targets={"S3Targets": [{"Path": "s3://acme-app-data/"}]})

gl.create_dev_endpoint(EndpointName="acme-dev", RoleArn=roles["GlueDevEndpointRole"],
                       NumberOfNodes=2)

print("glue: 3 jobs, 1 crawler, 1 dev endpoint")
