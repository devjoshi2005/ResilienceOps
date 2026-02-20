package terraform.security

import future.keywords.in

# Deny destructive actions
deny[msg] {
    forbidden = {"destroy", "delete", "remove", "terminate"}
    some line in input.lines
    contains(lower(line), forbidden[_])
    msg := sprintf("Destructive action forbidden: %v", [forbidden[_]])
}

# S3: Enforce private buckets
deny[msg] {
    s3 = input.resource.aws_s3_bucket[_]
    s3.public_access_block == null
    msg := "S3 bucket must have public_access_block enabled"
}

deny[msg] {
    s3 = input.resource.aws_s3_bucket[_]
    not s3.public_access_block.block_public_acls
    msg := "S3 must block public ACLs"
}

# EC2: No public ingress
deny[msg] {
    sg = input.resource.aws_security_group[_]
    some ingress in sg.ingress
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    msg := "EC2 security group cannot allow 0.0.0.0/0 ingress"
}

# IAM: Least privilege
deny[msg] {
    policy = input.resource.aws_iam_role_policy[_]
    some stmt in policy.statement
    stmt.effect == "Allow"
    stmt.action[_] == "*"
    msg := "IAM policy cannot use wildcard actions (*)"
}

# KMS: Enforce key policies
deny[msg] {
    kms = input.resource.aws_kms_key[_]
    kms.enable_key_rotation == false
    msg := "KMS key must have rotation enabled"
}

deny[msg] {
    kms = input.resource.aws_kms_key[_]
    not kms.policy
    msg := "KMS key must have policy defined"
}

# EKS: Secure cluster
deny[msg] {
    eks = input.resource.aws_eks_cluster[_]
    eks.resources_vpc_config.public_access_cidrs[_] == "0.0.0.0/0"
    msg := "EKS cluster cannot allow public access from 0.0.0.0/0"
}

deny[msg] {
    eks = input.resource.aws_eks_cluster[_]
    eks.version < "1.25"
    msg := "EKS cluster must use version 1.25 or higher"
}