variable "cluster_name" {
  type = string
}

variable "version" {
  type    = string
  default = "1.29"
}

variable "node_instance_type" {
  type    = string
  default = "m6i.xlarge"
}

variable "subnet_ids" {
  type = list(string)
}

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.version
  role_arn = aws_iam_role.cluster.arn
  vpc_config {
    subnet_ids = var.subnet_ids
  }
}

resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-eks"
  assume_role_policy = data.aws_iam_policy_document.eks-assume.json
}

data "aws_iam_policy_document" "eks-assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "default"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  scaling_config {
    desired_size = 3
    max_size     = 5
    min_size     = 3
  }
  instance_types = [var.node_instance_type]
}

resource "aws_iam_role" "node" {
  name = "${var.cluster_name}-node"
  assume_role_policy = data.aws_iam_policy_document.node-assume.json
}

data "aws_iam_policy_document" "node-assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

output "kubeconfig" {
  value     = aws_eks_cluster.this.identity[0].oidc[0].issuer
  sensitive = true
}
