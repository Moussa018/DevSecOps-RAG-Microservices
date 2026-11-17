data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "node" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private[0].id
  vpc_security_group_ids = [aws_security_group.node.id]
  iam_instance_profile   = aws_iam_instance_profile.node.name
  monitoring             = true

  metadata_options {
    http_tokens = "required" # IMDSv2 obligatoire
    # 2 : les pods (un saut de plus) doivent joindre le service de metadonnees pour obtenir le jeton IAM
    # de Bedrock. Seuls ingestion et rag y sont autorises par NetworkPolicy. Limite connue : sur k3s il n'y a
    # pas d'identite par pod ; sur EKS, utiliser IRSA / Pod Identity.
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = 60
    volume_type = "gp3"
    encrypted   = true
    kms_key_id  = aws_kms_key.main.arn
  }

  user_data = templatefile("${path.module}/templates/user-data.sh.tftpl", {
    region   = var.region
    registry = "${local.account_id}.dkr.ecr.${var.region}.amazonaws.com"
    secret   = aws_secretsmanager_secret.jwt.id
    bucket   = aws_s3_bucket.release.id
    llm      = var.llm_model_id
    embed    = var.embed_model_id
  })
  user_data_replace_on_change = true

  tags       = { Name = "${var.project}-k3s" }
  depends_on = [aws_nat_gateway.nat]
}

# ---- ALB public : seul point d'entree ----
resource "aws_lb" "public" {
  name_prefix                = "rag-"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "istio" {
  name_prefix = "rag-"
  port        = 30080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  health_check {
    path    = "/"
    matcher = "200-499" # l'ingress Istio repond 404 hors /api/ : il est vivant
  }
}

resource "aws_lb_target_group_attachment" "node" {
  target_group_arn = aws_lb_target_group.istio.arn
  target_id        = aws_instance.node.id
  port             = 30080
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  protocol          = "HTTP" # AVD-AWS-0054 : accepte pour la demo, voir .trivyignore
  default_action {
    type             = var.certificate_arn == "" ? "forward" : "redirect"
    target_group_arn = var.certificate_arn == "" ? aws_lb_target_group.istio.arn : null
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
    target_group_arn = aws_lb_target_group.istio.arn
  }
}
