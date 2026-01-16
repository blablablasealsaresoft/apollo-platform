variable "name" { type = string }
variable "cidr" { type = string }
variable "az_count" { type = number default = 3 }

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_hostnames = true
  tags = {
    Name = var.name
    Project = "Apollo"
  }
}

resource "aws_subnet" "private" {
  count             = var.az_count
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.cidr, 4, count.index)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)
  tags = {
    Name = "${var.name}-private-${count.index}"
  }
}

data "aws_availability_zones" "available" {}

output "vpc_id" { value = aws_vpc.this.id }
output "private_subnets" { value = aws_subnet.private[*].id }
