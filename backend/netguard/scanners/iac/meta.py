"""Rule metadata for IaC and container-configuration checks."""

from __future__ import annotations

from netguard.enums import Confidence as C
from netguard.enums import Severity as S
from netguard.scanners.sast.rules import Rule


def R(id_, title, cat, sev, conf, cwe, desc, impact, fix, langs=("*",), expl="medium", refs=()):
    return Rule(id=id_, title=title, category=cat, severity=sev, confidence=conf, cwe=cwe,
                languages=langs, description=desc, impact=impact, remediation=fix,
                exploitability=expl, references=refs)


PUBLIC = "Public Exposure"
ENC = "Missing Encryption"
PRIV = "Excessive Privileges"
NET = "Network Exposure"
CFG = "Insecure Configuration"

RULES: dict[str, Rule] = {r.id: r for r in [
    # ---- Terraform ----------------------------------------------------------------------------
    R("tf.s3-public-acl", "Potential unintended public storage access", PUBLIC, S.HIGH, C.HIGH,
      "CWE-732", "An S3 bucket uses a public ACL (public-read / public-read-write).",
      "Anyone on the internet can read (or write) the objects in the bucket.",
      "Use acl = \"private\", enable the S3 Block Public Access settings and grant access through "
      "IAM policies or pre-signed URLs.", expl="high"),
    R("tf.s3-public-access-block-disabled", "S3 public access block disabled", PUBLIC, S.MEDIUM,
      C.HIGH, "CWE-732", "An S3 public access block setting is set to false.",
      "Bucket policies or ACLs can make data public without a guardrail.",
      "Set block_public_acls, block_public_policy, ignore_public_acls and "
      "restrict_public_buckets to true."),
    R("tf.sg-open-ingress", "Security group open to the internet", NET, S.HIGH, C.HIGH, "CWE-284",
      "An ingress rule allows 0.0.0.0/0 (or ::/0) on sensitive or all ports.",
      "Administrative or internal services are reachable from anywhere, inviting scanning and "
      "brute-force attacks.",
      "Restrict cidr_blocks to known ranges (VPN / office) or reference another security group; "
      "use a bastion or SSM for administration.", expl="high"),
    R("tf.rds-public", "Database instance publicly accessible", PUBLIC, S.HIGH, C.HIGH, "CWE-668",
      "publicly_accessible is true on a database instance.",
      "The database endpoint resolves to a public address and is reachable from the internet.",
      "Set publicly_accessible = false and reach the database from private subnets.", expl="high"),
    R("tf.rds-unencrypted", "Database storage not encrypted", ENC, S.MEDIUM, C.MEDIUM, "CWE-311",
      "storage_encrypted is false or not set on a database instance.",
      "Data at rest (including snapshots) is stored unencrypted.",
      "Set storage_encrypted = true (and a kms_key_id where required)."),
    R("tf.ebs-unencrypted", "EBS volume not encrypted", ENC, S.MEDIUM, C.MEDIUM, "CWE-311",
      "encrypted is false or missing on an EBS volume.",
      "Data at rest on the volume and its snapshots is unencrypted.",
      "Set encrypted = true, or enable account-level default EBS encryption."),
    R("tf.iam-wildcard", "IAM policy grants all actions on all resources", PRIV, S.HIGH, C.HIGH,
      "CWE-269", "A policy statement allows Action \"*\" on Resource \"*\".",
      "Any principal with this policy has administrator-equivalent access; a single compromised "
      "credential compromises the account.",
      "Grant only the specific actions and resources required (least privilege).", expl="medium"),
    R("tf.lb-http-listener", "Load balancer listener uses plain HTTP", ENC, S.MEDIUM, C.MEDIUM,
      "CWE-319", "A load balancer listener serves HTTP without redirecting to HTTPS.",
      "Traffic, including credentials and cookies, can be intercepted or modified in transit.",
      "Use protocol HTTPS with an ACM certificate, or make the HTTP listener redirect to 443."),
    R("tf.imdsv1-enabled", "Instance metadata service v1 allowed", CFG, S.MEDIUM, C.HIGH,
      "CWE-918", "http_tokens = \"optional\" allows IMDSv1.",
      "An SSRF bug in the application can steal the instance's IAM credentials.",
      "Set metadata_options { http_tokens = \"required\" }."),
    R("tf.gcs-public", "GCS bucket accessible to all users", PUBLIC, S.HIGH, C.HIGH, "CWE-732",
      "A bucket IAM binding grants access to allUsers or allAuthenticatedUsers.",
      "Anyone on the internet (or any Google account) can access the bucket.",
      "Grant access to specific identities and enable uniform bucket-level access / public access "
      "prevention.", expl="high"),
    R("tf.gcp-firewall-open", "GCP firewall open to the internet", NET, S.HIGH, C.HIGH, "CWE-284",
      "A firewall rule allows 0.0.0.0/0 to sensitive ports.",
      "Administrative services are reachable from anywhere.",
      "Restrict source_ranges to trusted networks or use IAP TCP forwarding."),
    R("tf.azure-storage-public", "Azure storage allows public blob access", PUBLIC, S.HIGH,
      C.HIGH, "CWE-732", "Public blob/nested-item access is enabled on a storage account.",
      "Containers can be made anonymously readable.",
      "Set allow_nested_items_to_be_public / allow_blob_public_access to false.", expl="high"),
    R("tf.azure-storage-insecure-transport", "Azure storage accepts insecure transport", ENC,
      S.MEDIUM, C.HIGH, "CWE-319", "HTTPS-only is disabled or the minimum TLS version is below 1.2.",
      "Storage traffic may be sent unencrypted or with deprecated protocols.",
      "Set enable_https_traffic_only = true and min_tls_version = \"TLS1_2\"."),
    R("tf.azure-nsg-open", "Azure NSG open to the internet", NET, S.HIGH, C.HIGH, "CWE-284",
      "An inbound allow rule from * / 0.0.0.0/0 targets sensitive ports.",
      "Administrative services are reachable from anywhere.",
      "Restrict source_address_prefix to trusted ranges or use Azure Bastion."),
    # ---- Kubernetes ---------------------------------------------------------------------------
    R("k8s.privileged-container", "Privileged container", PRIV, S.HIGH, C.HIGH, "CWE-250",
      "A container runs with securityContext.privileged: true.",
      "The container has nearly full access to the host kernel and devices; a container escape is "
      "trivial.", "Remove privileged: true and add only the specific capabilities needed.",
      expl="high"),
    R("k8s.privilege-escalation", "Privilege escalation allowed", PRIV, S.MEDIUM, C.MEDIUM,
      "CWE-269", "allowPrivilegeEscalation is true, or not set (Kubernetes defaults it to true).",
      "A process can gain more privileges than its parent (setuid binaries).",
      "Set securityContext.allowPrivilegeEscalation: false."),
    R("k8s.run-as-root", "Container may run as root", PRIV, S.MEDIUM, C.MEDIUM, "CWE-250",
      "runAsNonRoot is not enforced (or runAsUser is 0).",
      "A compromised process runs as root inside the container, widening the impact of any escape.",
      "Set securityContext.runAsNonRoot: true and a non-zero runAsUser."),
    R("k8s.writable-root-fs", "Writable root filesystem", CFG, S.LOW, C.MEDIUM, "CWE-732",
      "readOnlyRootFilesystem is not true.",
      "An attacker can modify binaries or drop tools inside the container.",
      "Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes where needed."),
    R("k8s.dangerous-capabilities", "Dangerous Linux capabilities added", PRIV, S.HIGH, C.HIGH,
      "CWE-250", "Capabilities such as SYS_ADMIN, NET_ADMIN, SYS_PTRACE or ALL are added.",
      "These capabilities enable container escape or network manipulation.",
      "Drop ALL capabilities and add back only what is required."),
    R("k8s.host-namespace", "Pod shares host namespaces", PRIV, S.HIGH, C.HIGH, "CWE-668",
      "hostNetwork, hostPID or hostIPC is true.",
      "The pod can see host processes/network and attack other workloads.",
      "Remove hostNetwork/hostPID/hostIPC unless absolutely required."),
    R("k8s.hostpath-volume", "hostPath volume mounted", PRIV, S.MEDIUM, C.HIGH, "CWE-668",
      "A hostPath volume exposes the node filesystem to the pod (docker.sock or / is critical).",
      "A compromised pod can read or modify the node, or take over the container runtime.",
      "Use emptyDir, PersistentVolumes or projected volumes instead of hostPath."),
    R("k8s.mutable-image-tag", "Image uses a mutable tag", CFG, S.MEDIUM, C.HIGH, "CWE-494",
      "The image has no tag or uses :latest.",
      "Deployments are not reproducible and a compromised registry tag silently changes what runs.",
      "Pin an immutable version tag or, better, an image digest (image@sha256:...)."),
    R("k8s.no-resource-limits", "No resource limits", CFG, S.LOW, C.MEDIUM, "CWE-770",
      "The container has no CPU/memory limits.",
      "A compromised or buggy container can exhaust node resources (denial of service).",
      "Set resources.limits (and requests) for cpu and memory."),
    R("k8s.cluster-admin-binding", "Binding to cluster-admin", PRIV, S.HIGH, C.HIGH, "CWE-269",
      "A (Cluster)RoleBinding grants the cluster-admin role.",
      "The subject has unrestricted control of the cluster.",
      "Bind narrowly scoped roles instead of cluster-admin."),
    R("k8s.rbac-wildcard", "RBAC role uses wildcards", PRIV, S.HIGH, C.HIGH, "CWE-269",
      "A Role/ClusterRole allows verbs \"*\" on resources \"*\".",
      "Equivalent to administrator access within the role's scope.",
      "List the specific verbs and resources required."),
    R("k8s.service-exposed", "Service exposed outside the cluster", NET, S.INFO, C.HIGH, "CWE-668",
      "A Service of type LoadBalancer or NodePort exposes pods externally.",
      "Confirm the workload is meant to be reachable from outside the cluster.",
      "Prefer ClusterIP behind an authenticated ingress; restrict loadBalancerSourceRanges."),
    R("k8s.ingress-no-tls", "Ingress without TLS", ENC, S.LOW, C.MEDIUM, "CWE-319",
      "An Ingress has no tls section.", "Traffic to the ingress is unencrypted.",
      "Add a tls section with a certificate secret (cert-manager can automate this)."),
    # ---- CloudFormation -----------------------------------------------------------------------
    R("cfn.s3-public-acl", "Potential unintended public storage access", PUBLIC, S.HIGH, C.HIGH,
      "CWE-732", "An S3 bucket has AccessControl PublicRead / PublicReadWrite.",
      "Anyone on the internet can read (or write) the bucket.",
      "Use AccessControl: Private and PublicAccessBlockConfiguration.", expl="high"),
    R("cfn.sg-open-ingress", "Security group open to the internet", NET, S.HIGH, C.HIGH, "CWE-284",
      "An ingress rule allows 0.0.0.0/0 on sensitive ports.",
      "Administrative services are reachable from anywhere.",
      "Restrict CidrIp to trusted ranges.", expl="high"),
    R("cfn.rds-public", "Database instance publicly accessible", PUBLIC, S.HIGH, C.HIGH,
      "CWE-668", "PubliclyAccessible is true.", "The database is reachable from the internet.",
      "Set PubliclyAccessible: false.", expl="high"),
    R("cfn.unencrypted-storage", "Storage not encrypted", ENC, S.MEDIUM, C.MEDIUM, "CWE-311",
      "RDS StorageEncrypted or EBS Encrypted is false/missing.",
      "Data at rest is unencrypted.", "Set StorageEncrypted / Encrypted: true."),
]}
