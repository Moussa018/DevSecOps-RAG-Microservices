# Acces prive a Amazon Bedrock : les appels au LLM ne traversent jamais Internet.
# Authentification par role IAM du noeud (aucune cle d'API a stocker ni a faire tourner).
locals {
  # "eu.anthropic.claude-..." est un profil d'inference ; le modele de base n'a pas le prefixe de zone
  llm_base = replace(var.llm_model_id, "/^(eu|us|apac)\\./", "")

  bedrock_resources = [
    "arn:aws:bedrock:*::foundation-model/${local.llm_base}",
    "arn:aws:bedrock:*::foundation-model/${var.embed_model_id}",
    "arn:aws:bedrock:*:${local.account_id}:inference-profile/${var.llm_model_id}",
  ]
}

resource "aws_security_group" "endpoint" {
  name_prefix = "${var.project}-endpoint-"
  description = "VPC endpoint Bedrock"
  vpc_id      = aws_vpc.main.id
  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_from_node" {
  security_group_id            = aws_security_group.endpoint.id
  description                  = "HTTPS depuis le noeud uniquement"
  referenced_security_group_id = aws_security_group.node.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_endpoint" "bedrock" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private[0].id]
  security_group_ids  = [aws_security_group.endpoint.id]
  private_dns_enabled = true

  # Meme si le noeud est compromis, l'endpoint refuse tout autre modele
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["bedrock:InvokeModel"]
      Resource  = local.bedrock_resources
    }]
  })
}
