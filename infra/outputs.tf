output "app_url" {
  value = "${var.certificate_arn == "" ? "http" : "https"}://${aws_lb.public.dns_name}/api/query"
}

output "instance_id" {
  description = "Core node (k3s server): the CI deploys through this one. Put it in the GitHub secret INSTANCE_ID."
  value       = aws_instance.core.id
}

output "worker_instance_ids" {
  value = { for k, i in aws_instance.worker : k => i.id }
}

output "ssm_session" {
  description = "Administrator access without SSH"
  value       = "aws ssm start-session --target ${aws_instance.core.id} --region ${var.region}"
}

output "anthropic_secret_id" {
  description = "Set the API key once: aws secretsmanager put-secret-value --secret-id <this> --secret-string <key>"
  value       = aws_secretsmanager_secret.anthropic.id
}

output "github_actions_role_arn" {
  description = "Put it in the GitHub secret AWS_ROLE_ARN"
  value       = aws_iam_role.gha.arn
}

output "release_bucket" {
  value = aws_s3_bucket.release.id
}

output "ecr_registry" {
  value = "${local.account_id}.dkr.ecr.${var.region}.amazonaws.com"
}
