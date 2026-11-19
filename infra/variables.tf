variable "region" {
  type    = string
  default = "eu-west-3"
}

variable "project" {
  type    = string
  default = "rag-secure"
}

variable "github_repo" {
  description = "GitHub repository allowed to deploy, as owner/name (OIDC, no AWS keys)."
  type        = string
}

variable "create_oidc_provider" {
  description = "Set to false if the GitHub OIDC provider already exists in the account."
  type        = bool
  default     = true
}

variable "allowed_cidrs" {
  description = "Addresses allowed to reach the ALB. Restrict to your IP (x.x.x.x/32) for the demo."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "instance_types" {
  description = "Instance type of each node. The workers load an embedding model in memory: keep at least 4 GB."
  type        = map(string)
  default = {
    core   = "t3.large"  # k3s server, Traefik, gateway, Qdrant, cert-manager
    ingest = "t3.medium" # ingestion-service
    query  = "t3.medium" # rag-service
  }
}

variable "llm_model_id" {
  description = "Anthropic model used by rag-service. Check the current model identifiers before deploying."
  type        = string
  default     = "claude-haiku-5-5"
}

variable "certificate_arn" {
  description = "ACM certificate. Empty means HTTP only (acceptable for a demo, see .trivyignore)."
  type        = string
  default     = ""
}

variable "alert_email" {
  description = "E-mail address that receives budget alerts."
  type        = string
}

variable "budget_usd" {
  type    = number
  default = 15
}
