# Demo victim: a t3.micro in the default VPC with an instance role under the
# /forensics-demo/ IAM path. The path is the containment boundary: the
# revocation Lambda can only touch roles under it.

data "aws_vpc" "default" {
  default = true
}

# default-for-az matters: without it this lookup also finds the demo subnet
# below once it exists, the count flips to 0, and the next plan destroys it.
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

# Hardened accounts often delete the default subnets (the landing zone does).
# When there are none, create one throwaway subnet for the victim so the demo
# still deploys and destroys cleanly. No public IP: the decoy is tripped from
# outside, the victim never needs to reach the internet.
resource "aws_subnet" "demo" {
  count = var.deploy_victim && length(data.aws_subnets.default.ids) == 0 ? 1 : 0

  vpc_id                  = data.aws_vpc.default.id
  cidr_block              = var.demo_subnet_cidr
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project}-demo"
  }
}

locals {
  victim_subnet_id = length(data.aws_subnets.default.ids) > 0 ? data.aws_subnets.default.ids[0] : try(aws_subnet.demo[0].id, null)
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# Quarantine SG: zero ingress rules and zero egress rules. Declaring the
# resource with no egress blocks removes the default allow-all egress rule,
# so an instance moved here can neither receive nor initiate anything.
resource "aws_security_group" "quarantine" {
  name        = "${var.project}-quarantine"
  description = "Total isolation for instances under forensic investigation"
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name = "${var.project}-quarantine"
  }
}

resource "aws_iam_role" "victim" {
  count = var.deploy_victim ? 1 : 0

  name = "${var.project}-victim"
  path = local.demo_role_path

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Something real to revoke: the victim can use SSM, so a compromised
# credential taken from its metadata service has actual value.
resource "aws_iam_role_policy_attachment" "victim_ssm" {
  count = var.deploy_victim ? 1 : 0

  role       = aws_iam_role.victim[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "victim" {
  count = var.deploy_victim ? 1 : 0

  name = "${var.project}-victim"
  path = local.demo_role_path
  role = aws_iam_role.victim[0].name
}

resource "aws_instance" "victim" {
  count = var.deploy_victim ? 1 : 0

  ami                  = data.aws_ami.al2023.id
  instance_type        = "t3.micro"
  subnet_id            = local.victim_subnet_id
  iam_instance_profile = aws_iam_instance_profile.victim[0].name
  ebs_optimized        = true
  monitoring           = false

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  # Plants the decoy key where an attacker looks first. The secret also sits in
  # instance user data, which is fine: that is one more place a real intruder
  # would read it from, and either way it can only trip the alarm.
  user_data = local.decoy_enabled ? templatefile("${path.module}/templates/plant_decoy.sh.tftpl", {
    profile    = var.decoy_profile_name
    key_id     = aws_iam_access_key.decoy[0].id
    secret     = aws_iam_access_key.decoy[0].secret
    aws_region = var.aws_region
  }) : null
  user_data_replace_on_change = true

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = false # deliberately: the encrypted evidence copy is the pipeline's job
  }

  tags = {
    Name = "${var.project}-victim"
  }
}
