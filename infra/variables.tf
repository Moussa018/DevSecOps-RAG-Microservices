variable "region" {
  type    = string
  default = "eu-west-3"
}

variable "project" {
  type    = string
  default = "rag-secure"
}

variable "github_repo" {
  description = "Depot GitHub autorise a deployer, au format owner/name (OIDC, pas de cles AWS)."
  type        = string
}

variable "create_oidc_provider" {
  description = "Mettre false si le fournisseur OIDC GitHub existe deja dans le compte."
  type        = bool
  default     = true
}

variable "allowed_cidrs" {
  description = "Adresses autorisees a joindre l'ALB. Restreignez a votre IP (x.x.x.x/32) pour la demo."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "instance_type" {
  description = "8 Go de RAM suffisent : cert-manager + ingress-nginx + Qdrant + 3 services (le LLM est externe)."
  type        = string
  default     = "t3.large"
}

variable "llm_model_id" {
  description = "Modele de generation Bedrock (profil d'inference EU). A verifier dans la console Bedrock de votre region, et activer l'acces au modele."
  type        = string
  default     = "eu.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "embed_model_id" {
  description = "Modele d'embeddings Bedrock. La dimension (1024) est fixee dans services/*/llm.py."
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "certificate_arn" {
  description = "Certificat ACM. Vide = HTTP seulement (acceptable pour une demo, voir .trivyignore)."
  type        = string
  default     = ""
}

variable "alert_email" {
  description = "E-mail qui recoit les alertes de budget."
  type        = string
}

variable "budget_usd" {
  type    = number
  default = 15
}
