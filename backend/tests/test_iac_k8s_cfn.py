import json
import textwrap

from netguard.scanners.base import ScanContext
from netguard.scanners.iac.cloudformation import scan_cloudformation
from netguard.scanners.iac.kubernetes import scan_kubernetes
from netguard.scanners.registry import get_scanner

SECURE_POD = """\
apiVersion: v1
kind: Pod
metadata: {name: ok}
spec:
  securityContext: {runAsNonRoot: true, runAsUser: 1000}
  containers:
    - name: app
      image: registry.example.com/app:1.4.2
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      resources:
        limits: {cpu: 500m, memory: 256Mi}
"""


def k8s(src):
    return scan_kubernetes("k8s/app.yaml", textwrap.dedent(src))


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


def test_hardened_pod_has_no_findings():
    assert scan_kubernetes("p.yaml", SECURE_POD) == []


def test_privileged_deployment_reports_precise_lines():
    src = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: nginx:latest
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN"]
"""
    fs = {f.rule_id: f for f in scan_kubernetes("k8s/web.yaml", src)}
    assert {"k8s.privileged-container", "k8s.host-namespace", "k8s.dangerous-capabilities",
            "k8s.mutable-image-tag", "k8s.run-as-root", "k8s.writable-root-fs",
            "k8s.no-resource-limits"} <= set(fs)
    assert fs["k8s.privileged-container"].line == 13 and fs["k8s.privileged-container"].severity.value == "high"
    assert fs["k8s.host-namespace"].line == 8
    assert fs["k8s.mutable-image-tag"].line == 11 and "nginx:latest" in fs["k8s.mutable-image-tag"].description
    assert fs["k8s.dangerous-capabilities"].line == 15
    assert fs["k8s.privileged-container"].extra["resource"] == "Deployment/web"
    assert fs["k8s.privileged-container"].file_path == "k8s/web.yaml"
    # privileged already implies escalation; not double-reported
    assert "k8s.privilege-escalation" not in fs


def test_untagged_and_digest_images():
    def hit(image):
        src = SECURE_POD.replace("registry.example.com/app:1.4.2", image)
        return "k8s.mutable-image-tag" in rule_ids(scan_kubernetes("p.yaml", src))

    assert hit("nginx") and hit("nginx:latest") and hit("reg.io:5000/team/app")
    assert not hit("nginx:1.25") and not hit("nginx@sha256:" + "a" * 64) and not hit("reg.io:5000/app:2")


def test_hostpath_and_missing_security_context():
    src = """\
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  volumes:
    - name: sock
      hostPath: {path: /var/run/docker.sock}
  containers:
    - name: c
      image: app:1
      resources: {limits: {cpu: 1}}
"""
    fs = {f.rule_id: f for f in scan_kubernetes("p.yaml", src)}
    assert "k8s.hostpath-volume" in fs and "sensitive host path" in fs["k8s.hostpath-volume"].description
    assert {"k8s.privilege-escalation", "k8s.run-as-root", "k8s.writable-root-fs"} <= set(fs)


def test_pod_level_security_context_is_honoured_and_cronjob_and_multidoc():
    cron = """\
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          securityContext: {runAsNonRoot: true}
          containers:
            - name: j
              image: job:2
              securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true}
              resources: {limits: {cpu: 1}}
---
apiVersion: v1
kind: Service
metadata: {name: s}
spec: {type: LoadBalancer}
"""
    assert rule_ids(scan_kubernetes("c.yaml", cron)) == ["k8s.service-exposed"]


def test_rbac_ingress_and_service():
    crb = "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: b}\nroleRef:\n  kind: ClusterRole\n  name: cluster-admin\n"
    assert rule_ids(scan_kubernetes("r.yaml", crb)) == ["k8s.cluster-admin-binding"]
    role = "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: r}\nrules:\n  - apiGroups: ['']\n    resources: ['*']\n    verbs: ['*']\n"
    (f,) = scan_kubernetes("r.yaml", role)
    assert f.rule_id == "k8s.rbac-wildcard" and f.line == 5
    ing = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: i}\nspec:\n  rules: []\n"
    assert rule_ids(scan_kubernetes("i.yaml", ing)) == ["k8s.ingress-no-tls"]
    assert scan_kubernetes("i.yaml", ing.replace("rules: []", "tls: [{hosts: [a.b]}]")) == []


def test_non_kubernetes_helm_and_invalid_yaml_are_ignored():
    assert scan_kubernetes("a.yaml", "name: app\nversion: 1\n") == []
    assert scan_kubernetes("t.yaml", "apiVersion: v1\nkind: Pod\nspec: {{ .Values.x }}\n") == []
    assert scan_kubernetes("b.yaml", "apiVersion: v1\nkind: Pod\n  bad: [unclosed\n") == []


def test_inline_suppression():
    src = SECURE_POD.replace("image: registry.example.com/app:1.4.2", "image: nginx  # netguard:ignore k8s.mutable-image-tag")
    assert scan_kubernetes("p.yaml", src) == []


CFN = """\
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: x
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      DBName: !Ref Name
  Vol:
    Type: AWS::EC2::Volume
    Properties:
      Encrypted: false
"""


def test_cloudformation_yaml_with_intrinsic_tags():
    fs = scan_cloudformation("infra/t.yaml", CFN)
    assert sorted((f.rule_id, f.line) for f in fs) == [
        ("cfn.rds-public", 23), ("cfn.s3-public-acl", 6), ("cfn.sg-open-ingress", 15),
        ("cfn.unencrypted-storage", 23), ("cfn.unencrypted-storage", 28)]


def test_cloudformation_json_and_negatives():
    tpl = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
        "B": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicReadWrite"}},
        "OK": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "Private"}}}}
    fs = scan_cloudformation("t.json", json.dumps(tpl, indent=2))
    assert [f.rule_id for f in fs] == ["cfn.s3-public-acl"] and fs[0].line > 1
    assert scan_cloudformation("x.yaml", "foo: bar\n") == []
    assert scan_cloudformation("x.yaml", "AWSTemplateFormatVersion: [") == []


def test_iac_scanner_over_a_directory_and_registration(tmp_path):
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra/storage.tf").write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
    (tmp_path / "k8s.yaml").write_text(SECURE_POD.replace("app:1.4.2", "app:latest"))
    (tmp_path / "README.md").write_text("apiVersion: kind:")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules/x.tf").write_text('resource "aws_s3_bucket" "b" {\n acl = "public-read"\n}\n')
    scanner = get_scanner("iac")
    assert scanner.info().available
    res = scanner.scan(ScanContext(root=tmp_path))
    assert sorted((f.file_path, f.rule_id) for f in res.findings) == [
        ("infra/storage.tf", "tf.s3-public-acl"), ("k8s.yaml", "k8s.mutable-image-tag")]
    assert res.findings[0].title and res.metadata["rules"] >= 30
