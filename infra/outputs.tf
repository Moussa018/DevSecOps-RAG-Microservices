output "app_url" {
  value = "${var.certificate_arn == "" ? "http" : "https"}://${aws_lb.public.dns_name}/api/query"
}

output "instance_id" {
  value = aws_instance.node.id
}

output "ssm_session" {
  description = "Acces administrateur sans SSH"
  value       = "aws ssm start-session --target ${aws_instance.node.id} --region ${var.region}"
}

output "github_actions_role_arn" {
  description = "A mettre dans le secret GitHub AWS_ROLE_ARN"
  value       = aws_iam_role.gha.arn
}

output "release_bucket" {
  value = aws_s3_bucket.release.id
}

output "ecr_registry" {
  value = "${local.account_id}.dkr.ecr.${var.region}.amazonaws.com"
}
