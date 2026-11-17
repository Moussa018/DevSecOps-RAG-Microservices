terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.80" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = var.project, ManagedBy = "terraform", Purpose = "academic" }
  }
}

data "aws_caller_identity" "me" {}
data "aws_availability_zones" "az" { state = "available" }

locals {
  azs        = slice(data.aws_availability_zones.az.names, 0, 2)
  account_id = data.aws_caller_identity.me.account_id
  services   = ["gateway", "ingestion-service", "rag-service"]
}
