# ---------------------------------------------------------------------------------------------------------
# Security groups. No SSH, no bastion: administration goes through SSM Session Manager.
# There is NO rule between the ingest and the query security groups: a packet from one to the other is
# dropped before it reaches a pod. Pod traffic between nodes travels inside UDP 8472 (k3s VXLAN), so
# per-service port filtering stays with NetworkPolicy and mutual TLS.
# ---------------------------------------------------------------------------------------------------------
locals {
  workers = toset(["ingest", "query"])
}

resource "aws_security_group" "alb" {
  name_prefix = "${var.project}-alb-"
  description = "Public ALB"
  vpc_id      = aws_vpc.main.id
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "core" {
  name_prefix = "${var.project}-core-"
  description = "k3s server node (core subnet)"
  vpc_id      = aws_vpc.main.id
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "worker" {
  for_each    = local.workers
  name_prefix = "${var.project}-${each.key}-"
  description = "k3s agent node (${each.key} subnet)"
  vpc_id      = aws_vpc.main.id
  lifecycle { create_before_destroy = true }
}

# ---- ALB <-> core ----
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  count             = length(var.allowed_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from allowed addresses"
  cidr_ipv4         = var.allowed_cidrs[count.index]
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  count             = length(var.allowed_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from allowed addresses"
  cidr_ipv4         = var.allowed_cidrs[count.index]
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_core" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To Traefik on the core node"
  referenced_security_group_id = aws_security_group.core.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "core_from_alb" {
  security_group_id            = aws_security_group.core.id
  description                  = "Only the ALB, only port 80"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

# ---- core <-> workers (k3s API, kubelet, VXLAN) ----
resource "aws_vpc_security_group_ingress_rule" "core_api_from_worker" {
  for_each                     = aws_security_group.worker
  security_group_id            = aws_security_group.core.id
  description                  = "k3s API from the ${each.key} node"
  referenced_security_group_id = each.value.id
  from_port                    = 6443
  to_port                      = 6443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "core_vxlan_from_worker" {
  for_each                     = aws_security_group.worker
  security_group_id            = aws_security_group.core.id
  description                  = "Pod network (VXLAN) from the ${each.key} node"
  referenced_security_group_id = each.value.id
  from_port                    = 8472
  to_port                      = 8472
  ip_protocol                  = "udp"
}

resource "aws_vpc_security_group_egress_rule" "core_kubelet_to_worker" {
  for_each                     = aws_security_group.worker
  security_group_id            = aws_security_group.core.id
  description                  = "kubelet of the ${each.key} node"
  referenced_security_group_id = each.value.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "core_vxlan_to_worker" {
  for_each                     = aws_security_group.worker
  security_group_id            = aws_security_group.core.id
  description                  = "Pod network (VXLAN) to the ${each.key} node"
  referenced_security_group_id = each.value.id
  from_port                    = 8472
  to_port                      = 8472
  ip_protocol                  = "udp"
}

resource "aws_vpc_security_group_ingress_rule" "worker_kubelet_from_core" {
  for_each                     = aws_security_group.worker
  security_group_id            = each.value.id
  description                  = "kubelet, from the core node only"
  referenced_security_group_id = aws_security_group.core.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "worker_vxlan_from_core" {
  for_each                     = aws_security_group.worker
  security_group_id            = each.value.id
  description                  = "Pod network (VXLAN), from the core node only"
  referenced_security_group_id = aws_security_group.core.id
  from_port                    = 8472
  to_port                      = 8472
  ip_protocol                  = "udp"
}

resource "aws_vpc_security_group_egress_rule" "worker_api_to_core" {
  for_each                     = aws_security_group.worker
  security_group_id            = each.value.id
  description                  = "k3s API on the core node"
  referenced_security_group_id = aws_security_group.core.id
  from_port                    = 6443
  to_port                      = 6443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "worker_vxlan_to_core" {
  for_each                     = aws_security_group.worker
  security_group_id            = each.value.id
  description                  = "Pod network (VXLAN) to the core node"
  referenced_security_group_id = aws_security_group.core.id
  from_port                    = 8472
  to_port                      = 8472
  ip_protocol                  = "udp"
}

# ---- Internet through the NAT gateway ----
# Open to every destination on 443 and 80 (ECR, package repositories, k3s, cert-manager, Anthropic API).
# A security group cannot filter by hostname: only the rag-service pod may actually use it for the API
# (NetworkPolicy). See README, section 7.5.
resource "aws_vpc_security_group_egress_rule" "core_https" {
  security_group_id = aws_security_group.core.id
  description       = "HTTPS out through the NAT"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "core_http" {
  security_group_id = aws_security_group.core.id
  description       = "HTTP out through the NAT (package repositories)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "worker_https" {
  for_each          = aws_security_group.worker
  security_group_id = each.value.id
  description       = "HTTPS out through the NAT"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "worker_http" {
  for_each          = aws_security_group.worker
  security_group_id = each.value.id
  description       = "HTTP out through the NAT (package repositories)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

# ---------------------------------------------------------------------------------------------------------
# One KMS key: volumes, secrets, logs, ECR
# ---------------------------------------------------------------------------------------------------------
resource "aws_kms_key" "main" {
  description             = "${var.project} encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RootAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = { ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${local.account_id}:*" } }
      }
    ]
  })
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.project}"
  target_key_id = aws_kms_key.main.key_id
}

# ---------------------------------------------------------------------------------------------------------
# Secrets. The JWT secret and the k3s join token are generated here and never appear in the repository.
# The Anthropic API key is created EMPTY: set it by hand so it never lands in the Terraform state:
#   aws secretsmanager put-secret-value --secret-id rag-secure/anthropic-api-key --secret-string <key>
# ---------------------------------------------------------------------------------------------------------
resource "random_password" "jwt" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "jwt" {
  name                    = "${var.project}/jwt-secret"
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "jwt" {
  secret_id     = aws_secretsmanager_secret.jwt.id
  secret_string = random_password.jwt.result
}

resource "random_password" "k3s_token" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "k3s_token" {
  name                    = "${var.project}/k3s-token"
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "k3s_token" {
  secret_id     = aws_secretsmanager_secret.k3s_token.id
  secret_string = random_password.k3s_token.result
}

resource "aws_secretsmanager_secret" "anthropic" {
  name                    = "${var.project}/anthropic-api-key"
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 0
}

# ---------------------------------------------------------------------------------------------------------
# ECR: one repository per service, immutable tags, scan on push, encrypted
# ---------------------------------------------------------------------------------------------------------
resource "aws_ecr_repository" "svc" {
  for_each             = toset(local.services)
  name                 = "${var.project}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.main.arn
  }
}

resource "aws_ecr_lifecycle_policy" "svc" {
  for_each   = aws_ecr_repository.svc
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 10 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 10 }
      action       = { type = "expire" }
    }]
  })
}

# ---------------------------------------------------------------------------------------------------------
# Release bucket (CI -> core node)
# ---------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket" "release" {
  bucket_prefix = "${var.project}-release-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "release" {
  bucket                  = aws_s3_bucket.release.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "release" {
  bucket = aws_s3_bucket.release.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "release" {
  bucket = aws_s3_bucket.release.id
  versioning_configuration { status = "Enabled" }
}
