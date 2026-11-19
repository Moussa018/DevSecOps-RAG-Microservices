# ---- One minimal role per node ----
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

locals {
  node_roles = toset(["core", "ingest", "query"])
}

resource "aws_iam_role" "node" {
  for_each           = local.node_roles
  name_prefix        = "${var.project}-${each.key}-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  for_each   = aws_iam_role.node
  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# core: runs the deployment, so it reads the three secrets, the release bucket and pulls from ECR
data "aws_iam_policy_document" "core" {
  statement {
    sid       = "EcrToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "EcrPull"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [for r in aws_ecr_repository.svc : r.arn]
  }
  statement {
    sid     = "ReadSecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.jwt.arn,
      aws_secretsmanager_secret.k3s_token.arn,
      aws_secretsmanager_secret.anthropic.arn,
    ]
  }
  statement {
    sid       = "ReadRelease"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.release.arn, "${aws_s3_bucket.release.arn}/*"]
  }
  statement {
    sid       = "Decrypt"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.main.arn]
  }
}

# workers: only the k3s join token. Images are pulled with the cluster pull secret, not with this role.
data "aws_iam_policy_document" "worker" {
  statement {
    sid       = "ReadK3sToken"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.k3s_token.arn]
  }
  statement {
    sid       = "Decrypt"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "node" {
  for_each = aws_iam_role.node
  name     = "least-privilege"
  role     = each.value.id
  policy   = each.key == "core" ? data.aws_iam_policy_document.core.json : data.aws_iam_policy_document.worker.json
}

resource "aws_iam_instance_profile" "node" {
  for_each    = aws_iam_role.node
  name_prefix = "${var.project}-${each.key}-"
  role        = each.value.name
}

# ---- GitHub Actions: OIDC, no AWS key stored ----
resource "aws_iam_openid_connect_provider" "github" {
  count           = var.create_oidc_provider ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

locals {
  oidc_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "gha_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main"] # main branch only
    }
  }
}

resource "aws_iam_role" "gha" {
  name_prefix        = "${var.project}-gha-"
  assume_role_policy = data.aws_iam_policy_document.gha_assume.json
}

data "aws_iam_policy_document" "gha" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages"
    ]
    resources = [for r in aws_ecr_repository.svc : r.arn]
  }
  statement {
    actions   = ["s3:PutObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.release.arn, "${aws_s3_bucket.release.arn}/*"]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.main.arn]
  }
  statement {
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ssm:${var.region}::document/AWS-RunShellScript", aws_instance.core.arn]
  }
  statement {
    actions   = ["ssm:GetCommandInvocation"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "gha" {
  name   = "ci-deploy"
  role   = aws_iam_role.gha.id
  policy = data.aws_iam_policy_document.gha.json
}
