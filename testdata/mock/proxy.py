"""HTTP shim in front of moto.

Two jobs:

  1. Repair moto responses the real AWS SDK rejects. moto serialises
     CodePipeline timestamps as ISO strings where the API models a number, so
     aws-sdk-go-v2 fails to deserialise and the service is skipped entirely.

  2. Enforce the AWS limits and failures moto does not model, so the code paths
     that exist purely to handle them are actually executed:
       - BatchGetProjects rejects more than 100 names
       - ListNodegroups can be made to fail, which is what spins a paginator
         loop that continues instead of breaking
"""

import datetime
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("MOCK_UPSTREAM", "http://127.0.0.1:5111")
FAIL_NODEGROUPS = os.environ.get("MOCK_FAIL_NODEGROUPS", "") == "1"

BATCH_GET_PROJECTS_MAX = 100

# moto returns a 500 for the identity-pool role APIs, so the proxy implements
# them itself. Without this the Cognito collector has nothing to read and the
# unauthenticated-role path cannot be exercised at all.
IDENTITY_POOL_ROLES = {}

# moto also returns a 500 for these, and because the SDK treats 500 as retryable
# each one costs backoff on every region. Stubbing them keeps the run fast and
# actually exercises the collector paths that read them.
CODE_INTERPRETERS = {}
BROWSERS = {}
USER_PROFILES = {}

HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "upgrade",
              "proxy-authenticate", "proxy-authorization", "te", "trailers"}


def to_epoch(value):
    if not isinstance(value, str):
        return value
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return value


TIMESTAMP_KEYS = ("created", "updated", "startTime", "lastUpdatedTime")


def walk_timestamps(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in TIMESTAMP_KEYS:
                node[k] = to_epoch(v)
            else:
                walk_timestamps(v)
    elif isinstance(node, list):
        for v in node:
            walk_timestamps(v)


def fix_codepipeline_timestamps(body):
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body
    walk_timestamps(doc)
    return json.dumps(doc).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _target(self):
        return self.headers.get("X-Amz-Target", "")

    def _region(self):
        # Credential=<key>/<date>/<region>/<service>/aws4_request
        auth = self.headers.get("Authorization", "")
        for part in auth.split():
            if part.startswith("Credential="):
                fields = part.split("=", 1)[1].split("/")
                if len(fields) > 2:
                    return fields[2]
        return "us-east-1"

    def _json(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/x-amz-json-1.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reject(self, status, code, message):
        body = json.dumps({"__type": code, "message": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/x-amz-json-1.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        target = self._target()

        # --- injected AWS behaviour moto does not model ---------------------
        if target.endswith(".BatchGetProjects"):
            try:
                names = json.loads(body).get("names", [])
            except ValueError:
                names = []
            if len(names) > BATCH_GET_PROJECTS_MAX:
                return self._reject(
                    400, "InvalidInputException",
                    "Can not process more than %d projects in one request"
                    % BATCH_GET_PROJECTS_MAX)

        if target.endswith("AWSCognitoIdentityService.SetIdentityPoolRoles"):
            try:
                doc = json.loads(body)
            except ValueError:
                doc = {}
            IDENTITY_POOL_ROLES[doc.get("IdentityPoolId", "")] = {
                "Roles": doc.get("Roles", {}),
                "RoleMappings": doc.get("RoleMappings", {}),
            }
            return self._json({})

        if target.endswith("AWSCognitoIdentityService.GetIdentityPoolRoles"):
            try:
                pid = json.loads(body).get("IdentityPoolId", "")
            except ValueError:
                pid = ""
            stored = IDENTITY_POOL_ROLES.get(pid, {"Roles": {}, "RoleMappings": {}})
            return self._json({"IdentityPoolId": pid, **stored})

        # --- AgentCore code interpreters and browsers (REST-JSON) ----------
        for kind, store, idKey, arnKey, listKey in (
            ("code-interpreters", CODE_INTERPRETERS, "codeInterpreterId",
             "codeInterpreterArn", "codeInterpreterSummaries"),
            ("browsers", BROWSERS, "browserId", "browserArn", "browserSummaries"),
        ):
            path = self.path.split("?")[0].rstrip("/")

            if path.endswith("/" + kind) or path == "/" + kind:
                region = self._region()

                if self.command == "PUT":
                    doc = json.loads(body or b"{}")
                    ident = "%s-%04d" % (kind.rstrip("s"), len(store) + 1)
                    store[(region, ident)] = {
                        idKey: ident,
                        arnKey: "arn:aws:bedrock-agentcore:%s:123456789012:%s/%s" % (region, kind, ident),
                        "name": doc.get("name", ident),
                        "executionRoleArn": doc.get("executionRoleArn", ""),
                        "status": "READY",
                    }
                    return self._json(store[(region, ident)])

                if self.command == "POST":
                    summaries = [{k: v for k, v in item.items() if k != "executionRoleArn"}
                                 for (r, _), item in store.items() if r == region]
                    return self._json({listKey: summaries})

            if "/" + kind + "/" in path and self.command == "GET":
                return self._json(store.get((self._region(), path.rsplit("/", 1)[-1]), {}))

        # --- SageMaker user profiles (JSON 1.1) ----------------------------
        if target in ("SageMaker.CreateUserProfile", "SageMaker.DescribeUserProfile",
                      "SageMaker.ListUserProfiles"):
            doc = json.loads(body or b"{}")
            key = (self._region(), doc.get("DomainId", ""), doc.get("UserProfileName", ""))

            if target.endswith(".CreateUserProfile"):
                USER_PROFILES[key] = doc
                return self._json({"UserProfileArn":
                                   "arn:aws:sagemaker:%s:123456789012:user-profile/%s/%s" % key})

            if target.endswith(".DescribeUserProfile"):
                stored = USER_PROFILES.get(key, {})
                return self._json({"DomainId": key[1], "UserProfileName": key[2],
                                   "UserSettings": stored.get("UserSettings", {})})

            if target.endswith(".ListUserProfiles"):
                return self._json({"UserProfiles": [
                    {"DomainId": d, "UserProfileName": u}
                    for r, d, u in USER_PROFILES if r == key[0]]})

        if FAIL_NODEGROUPS and "/node-groups" in self.path:
            return self._reject(403, "AccessDeniedException",
                                "not authorized to perform eks:ListNodegroups")

        # --- forward ---------------------------------------------------------
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP_BY_HOP}
        req = urllib.request.Request(UPSTREAM + self.path, data=body or None,
                                     headers=headers, method=self.command)
        try:
            resp = urllib.request.urlopen(req)
            status, out, rheaders = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            status, out, rheaders = e.code, e.read(), e.headers
        except Exception as e:
            return self._reject(502, "ProxyError", str(e))

        # --- repair ----------------------------------------------------------
        if target.startswith("CodePipeline_"):
            out = fix_codepipeline_timestamps(out)

        self.send_response(status)
        for k, v in rheaders.items():
            if k.lower() not in HOP_BY_HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5110
    print("proxy on %d -> %s  (fail-nodegroups=%s)" % (port, UPSTREAM, FAIL_NODEGROUPS))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
