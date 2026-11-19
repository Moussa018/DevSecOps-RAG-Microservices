# VPC: public subnets (ALB, NAT) and THREE private subnets, one per node:
#   core   10.0.1.0/24  AZ a  k3s server: Traefik, gateway, qdrant, cert-manager
#   ingest 10.0.2.0/24  AZ a  k3s agent : ingestion-service only
#   query  10.0.3.0/24  AZ b  k3s agent : rag-service only
# One NAT gateway for the three private subnets (cost).
locals {
  private_subnets = {
    core   = { cidr = "10.0.1.0/24", az = local.azs[0] }
    ingest = { cidr = "10.0.2.0/24", az = local.azs[0] }
    query  = { cidr = "10.0.3.0/24", az = local.azs[1] }
  }
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, 100 + count.index)
  availability_zone = local.azs[count.index]
  tags              = { Name = "${var.project}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  for_each          = local.private_subnets
  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az
  tags              = { Name = "${var.project}-${each.key}" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

# The default security group of the VPC lets nothing through
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}
