data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# ---- core: k3s server (Traefik, gateway, qdrant, cert-manager) ----
resource "aws_instance" "core" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_types["core"]
  subnet_id              = aws_subnet.private["core"].id
  vpc_security_group_ids = [aws_security_group.core.id]
  iam_instance_profile   = aws_iam_instance_profile.node["core"].name
  monitoring             = true

  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # pods cannot reach the metadata service
  }

  root_block_device {
    volume_size = 40
    volume_type = "gp3"
    encrypted   = true
    kms_key_id  = aws_kms_key.main.arn
  }

  user_data = templatefile("${path.module}/templates/user-data-server.sh.tftpl", {
    region           = var.region
    registry         = "${local.account_id}.dkr.ecr.${var.region}.amazonaws.com"
    jwt_secret       = aws_secretsmanager_secret.jwt.id
    k3s_secret       = aws_secretsmanager_secret.k3s_token.id
    anthropic_secret = aws_secretsmanager_secret.anthropic.id
    bucket           = aws_s3_bucket.release.id
    llm              = var.llm_model_id
  })
  user_data_replace_on_change = true

  tags       = { Name = "${var.project}-core" }
  depends_on = [aws_nat_gateway.nat, aws_iam_role_policy.node, aws_secretsmanager_secret_version.k3s_token]
}

# ---- workers: one k3s agent per business service, each in its own subnet ----
resource "aws_instance" "worker" {
  for_each               = local.workers
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_types[each.key]
  subnet_id              = aws_subnet.private[each.key].id
  vpc_security_group_ids = [aws_security_group.worker[each.key].id]
  iam_instance_profile   = aws_iam_instance_profile.node[each.key].name
  monitoring             = true

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 30 # the embedding model is part of the image
    volume_type = "gp3"
    encrypted   = true
    kms_key_id  = aws_kms_key.main.arn
  }

  user_data = templatefile("${path.module}/templates/user-data-agent.sh.tftpl", {
    region     = var.region
    k3s_secret = aws_secretsmanager_secret.k3s_token.id
    server_ip  = aws_instance.core.private_ip
    node_role  = each.key
  })
  user_data_replace_on_change = true

  tags       = { Name = "${var.project}-${each.key}" }
  depends_on = [aws_nat_gateway.nat, aws_iam_role_policy.node]
}

# ---- Public ALB: single entry point, towards Traefik on the core node ----
resource "aws_lb" "public" {
  name_prefix                = "rag-"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "ingress" {
  name_prefix = "rag-"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  health_check {
    path    = "/"
    matcher = "200-499" # Traefik answers 404 outside /api: it is alive
  }
}

resource "aws_lb_target_group_attachment" "core" {
  target_group_arn = aws_lb_target_group.ingress.arn
  target_id        = aws_instance.core.id
  port             = 80
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  protocol          = "HTTP" # AVD-AWS-0054: accepted for the demo, see .trivyignore
  default_action {
    type             = var.certificate_arn == "" ? "forward" : "redirect"
    target_group_arn = var.certificate_arn == "" ? aws_lb_target_group.ingress.arn : null
    dynamic "redirect" {
      for_each = var.certificate_arn == "" ? [] : [1]
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  count             = var.certificate_arn == "" ? 0 : 1
  load_balancer_arn = aws_lb.public.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ingress.arn
  }
}
