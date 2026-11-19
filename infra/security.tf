# Pas de SSH, pas de bastion : l'acces administrateur passe par SSM Session Manager.
resource "aws_security_group" "alb" {
  name_prefix = "${var.project}-alb-"
  description = "ALB public"
  vpc_id      = aws_vpc.main.id
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "node" {
  name_prefix = "${var.project}-node-"
  description = "Noeud k3s prive"
  vpc_id      = aws_vpc.main.id
  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  count             = length(var.allowed_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTP depuis les adresses autorisees"
  cidr_ipv4         = var.allowed_cidrs[count.index]
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  count             = length(var.allowed_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS depuis les adresses autorisees"
  cidr_ipv4         = var.allowed_cidrs[count.index]
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_node" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Vers ingress-nginx (NodePort)"
  referenced_security_group_id = aws_security_group.node.id
  from_port                    = 30080
  to_port                      = 30080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "node_from_alb" {
  security_group_id            = aws_security_group.node.id
  description                  = "Uniquement l'ALB, uniquement le NodePort d'ingress-nginx"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 30080
  to_port                      = 30080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "node_https" {
  security_group_id = aws_security_group.node.id
  description       = "Sortie HTTPS (ECR, SSM, S3, telechargement des modeles)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "node_http" {
  security_group_id = aws_security_group.node.id
  description       = "Sortie HTTP (depots dnf)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

# Cle KMS unique : volumes, secrets, journaux, ECR
resource "aws_kms_key" "main" {
  description             = "${var.project} chiffrement"
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

# Secret JWT genere par Terraform, jamais present dans le depot
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

# Depot ECR par service : tags immuables, scan a l'envoi, chiffre
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
      description  = "Garder les 10 dernieres images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 10 }
      action       = { type = "expire" }
    }]
  })
}

# Bucket de livraison des manifestes (CI -> noeud)
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
