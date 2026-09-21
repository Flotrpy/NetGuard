import textwrap

import pytest

from netguard.scanners.iac import hcl
from netguard.scanners.iac.terraform import scan_terraform


def scan(src):
    return scan_terraform("infra/main.tf", textwrap.dedent(src))


def ids(src):
    return sorted(f.rule_id for f in scan(src))


def test_hcl_parser_blocks_attrs_nested_and_multiline():
    blocks = hcl.parse(textwrap.dedent('''
        # comment
        resource "aws_security_group" "web" {
          name = "web" # trailing
          ingress {
            from_port   = 22
            cidr_blocks = [
              "0.0.0.0/0",
              "10.0.0.0/8",
            ]
          }
          policy = <<EOF
        {"a": 1}
        EOF
        }
        /* block
        comment */
        variable "x" {}
    '''))
    sg = blocks[0]
    assert (sg.kind, sg.type, sg.name) == ("resource", "aws_security_group", "web")
    assert sg.get("name") == '"web"' and sg.attrs["name"].line == 4
    ing = sg.blocks("ingress")[0]
    assert "0.0.0.0/0" in ing.get("cidr_blocks") and ing.attrs["from_port"].line == 6
    assert sg.get("policy") == '{"a": 1}'
    assert hcl.unquote('"x"') == "x"


def test_s3_public_acl_reports_file_and_line():
    (f,) = scan('''
        resource "aws_s3_bucket" "data" {
          bucket = "my-data"
          acl    = "public-read"
        }
    ''')
    assert f.rule_id == "tf.s3-public-acl" and f.severity.value == "high"
    assert (f.file_path, f.line, f.language) == ("infra/main.tf", 4, "terraform")
    assert f.title == "Potential unintended public storage access"
    assert f.extra["resource"] == "aws_s3_bucket.data" and f.asset.type == "iac"
    assert f.remediation and f.impact


def test_private_bucket_and_block_settings():
    assert ids('resource "aws_s3_bucket" "b" {\n acl = "private"\n}\n') == []
    assert ids('resource "aws_s3_bucket_public_access_block" "p" {\n block_public_acls = true\n}\n') == []
    assert ids('resource "aws_s3_bucket_public_access_block" "p" {\n block_public_acls = false\n restrict_public_buckets = true\n}\n') == [
        "tf.s3-public-access-block-disabled"]


@pytest.mark.parametrize("ingress,flagged", [
    ('from_port = 22\nto_port = 22\nprotocol = "tcp"\ncidr_blocks = ["0.0.0.0/0"]', True),
    ('from_port = 3389\nto_port = 3389\nprotocol = "tcp"\ncidr_blocks = ["0.0.0.0/0"]', True),
    ('from_port = 0\nto_port = 0\nprotocol = "-1"\ncidr_blocks = ["0.0.0.0/0"]', True),
    ('from_port = 0\nto_port = 65535\nprotocol = "tcp"\ncidr_blocks = ["0.0.0.0/0"]', True),
    ('from_port = 22\nto_port = 22\nprotocol = "tcp"\nipv6_cidr_blocks = ["::/0"]', True),
    ('from_port = 443\nto_port = 443\nprotocol = "tcp"\ncidr_blocks = ["0.0.0.0/0"]', False),
    ('from_port = 22\nto_port = 22\nprotocol = "tcp"\ncidr_blocks = ["10.0.0.0/8"]', False),
])
def test_security_group_ingress(ingress, flagged):
    body = "\n".join("    " + line for line in ingress.splitlines())
    hits = ids(f'resource "aws_security_group" "sg" {{\n  ingress {{\n{body}\n  }}\n}}\n')
    assert (hits == ["tf.sg-open-ingress"]) is flagged


def test_security_group_rule_and_vpc_rule_resources():
    assert ids('resource "aws_security_group_rule" "r" {\n type = "ingress"\n from_port = 22\n to_port = 22\n protocol = "tcp"\n cidr_blocks = ["0.0.0.0/0"]\n}\n') == ["tf.sg-open-ingress"]
    assert ids('resource "aws_security_group_rule" "r" {\n type = "egress"\n from_port = 22\n to_port = 22\n protocol = "tcp"\n cidr_blocks = ["0.0.0.0/0"]\n}\n') == []
    assert ids('resource "aws_vpc_security_group_ingress_rule" "r" {\n from_port = 22\n to_port = 22\n ip_protocol = "tcp"\n cidr_ipv4 = "0.0.0.0/0"\n}\n') == ["tf.sg-open-ingress"]


def test_rds_and_ebs():
    assert ids('resource "aws_db_instance" "d" {\n publicly_accessible = true\n storage_encrypted = true\n}\n') == ["tf.rds-public"]
    assert ids('resource "aws_db_instance" "d" {\n storage_encrypted = false\n}\n') == ["tf.rds-unencrypted"]
    assert ids('resource "aws_db_instance" "d" {\n engine = "mysql"\n}\n') == ["tf.rds-unencrypted"]
    assert ids('resource "aws_db_instance" "d" {\n storage_encrypted = true\n publicly_accessible = false\n}\n') == []
    assert ids('resource "aws_ebs_volume" "v" {\n size = 10\n}\n') == ["tf.ebs-unencrypted"]
    assert ids('resource "aws_ebs_volume" "v" {\n encrypted = true\n}\n') == []


def test_iam_wildcards_in_heredoc_jsonencode_and_document():
    heredoc = 'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\nEOF\n}\n'
    assert ids(heredoc) == ["tf.iam-wildcard"]
    js = 'resource "aws_iam_role_policy" "p" {\n  policy = jsonencode({\n    Statement = [{\n      Effect = "Allow"\n      Action = "*"\n      Resource = "*"\n    }]\n  })\n}\n'
    assert ids(js) == ["tf.iam-wildcard"]
    doc = 'data "aws_iam_policy_document" "d" {\n  statement {\n    effect = "Allow"\n    actions = ["*"]\n    resources = ["*"]\n  }\n}\n'
    assert ids(doc) == ["tf.iam-wildcard"]
    scoped = 'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}\nEOF\n}\n'
    assert ids(scoped) == []
    deny = 'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}\nEOF\n}\n'
    assert ids(deny) == []


def test_lb_listener_and_imds():
    assert ids('resource "aws_lb_listener" "l" {\n protocol = "HTTP"\n default_action {\n  type = "forward"\n }\n}\n') == ["tf.lb-http-listener"]
    redirect = 'resource "aws_lb_listener" "l" {\n protocol = "HTTP"\n default_action {\n  type = "redirect"\n }\n}\n'
    assert ids(redirect) == []
    assert ids('resource "aws_instance" "i" {\n metadata_options {\n  http_tokens = "optional"\n }\n}\n') == ["tf.imdsv1-enabled"]
    assert ids('resource "aws_instance" "i" {\n metadata_options {\n  http_tokens = "required"\n }\n}\n') == []


def test_gcp_resources():
    assert ids('resource "google_storage_bucket_iam_member" "m" {\n member = "allUsers"\n role = "roles/storage.objectViewer"\n}\n') == ["tf.gcs-public"]
    assert ids('resource "google_storage_bucket_iam_member" "m" {\n member = "user:a@b.c"\n}\n') == []
    fw = 'resource "google_compute_firewall" "f" {\n source_ranges = ["0.0.0.0/0"]\n allow {\n  protocol = "tcp"\n  ports = ["22"]\n }\n}\n'
    assert ids(fw) == ["tf.gcp-firewall-open"]
    web = fw.replace('"22"', '"443"')
    assert ids(web) == []


def test_azure_resources():
    assert ids('resource "azurerm_storage_account" "s" {\n allow_nested_items_to_be_public = true\n}\n') == ["tf.azure-storage-public"]
    assert ids('resource "azurerm_storage_account" "s" {\n enable_https_traffic_only = false\n min_tls_version = "TLS1_0"\n}\n') == [
        "tf.azure-storage-insecure-transport"] * 2
    nsg = 'resource "azurerm_network_security_rule" "r" {\n direction = "Inbound"\n access = "Allow"\n source_address_prefix = "*"\n destination_port_range = "22"\n}\n'
    assert ids(nsg) == ["tf.azure-nsg-open"]
    assert ids(nsg.replace('"Inbound"', '"Outbound"')) == []


def test_inline_suppression_and_unparseable_input():
    src = 'resource "aws_s3_bucket" "b" {\n acl = "public-read" # netguard:ignore tf.s3-public-acl\n}\n'
    assert ids(src) == []
    assert scan("this is { not really } terraform ::: \n}}}}\n") == []
