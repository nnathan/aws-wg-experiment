terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
  }
}

provider "aws" {
  region = var.region
}

############################
# Variables
############################
variable "deployment_id" {
  type    = string
  default = "ritchie"
}

variable "region" {
  type    = string
  default = "ap-southeast-2"
}

variable "az" {
  type    = string
  default = "ap-southeast-2a"
}

variable "instance_type" {
  type    = string
  default = "c7i.xlarge"
}

############################
# Unique project identifier
############################
resource "random_uuid" "project" {}

############################
# Locals
############################
locals {
  # AWS EC2 keypair name (still used to allow initial SSH access; you also overwrite root authorized_keys)
  key_name = "naveen@c"

  name_pref  = var.deployment_id
  project_id = random_uuid.project.result

  # AWS subnet reserved addresses make .2/.3 unusable; use .4/.5/.6.
  src_ip = "10.80.1.4"
  mid_ip = "10.80.1.5"
  snk_ip = "10.80.1.6"

  # WireGuard UDP ports (separate ports on mid)
  wg0_port = 51820 # src <-> mid
  wg1_port = 51821 # mid <-> snk

  # WireGuard tunnel addressing (mid ends with .2)
  src_wg0_ip = "172.16.100.1/24"
  mid_wg0_ip = "172.16.100.2/24"

  snk_wg0_ip = "192.168.100.1/24"
  mid_wg1_ip = "192.168.100.2/24"

  # Pre-generated X25519 WireGuard keys (static, hardcoded)
  # Tunnel A: src<->mid (wg0)
  wg_a_src_priv = "gHffSe0nW0G9rgch3mqLaMO5ustBtJmZzRUx1F45Y0w="
  wg_a_src_pub  = "zh/wBla/kmApbl6fvTCJp7Cfy6Nit/RfAL+89Re6mVo="
  wg_a_mid_priv = "qCFc4L03ecqHSJuCOrtJyzDWZQomqV+pENkb1fu0ylA="
  wg_a_mid_pub  = "34oBwSojFrWdBf3HU1N7j9LZ3GcyyXQwygOSMsdbfE4="

  # Tunnel B: mid<->snk (wg1 on mid, wg0 on snk)
  wg_b_mid_priv = "kDArbobkT4iPtK1Y1/ZjaGg5631/nn0DTnJzhrY5C2w="
  wg_b_mid_pub  = "wID/oA6j9c+J85jVu3i57hH4FBQu6xs+isw109bW3Ao="
  wg_b_snk_priv = "gIAo2vEPRO2SUhhNwwdATCpQEttwLqFB4IiIAVNaOUU="
  wg_b_snk_pub  = "5GIN3bNusxo91u9J3VxjxN0IoxBdoiBKUmaUfoZeDmY="

  common_tags = {
    deployment_id = var.deployment_id
    project_uid   = local.project_id
    managed_by    = "terraform"
    project       = "wg-pktgen-lab"
  }
}

############################
# VPC + Internet
############################
resource "aws_vpc" "this" {
  cidr_block           = "10.80.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "${local.name_pref}-vpc"
  })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${local.name_pref}-igw"
  })
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.80.1.0/24"
  availability_zone       = var.az
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${local.name_pref}-subnet"
  })
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${local.name_pref}-rt"
  })
}

resource "aws_route" "default" {
  route_table_id         = aws_route_table.rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "subnet" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.rt.id
}

############################
# Security Group (open SSH + WG ports)
############################
resource "aws_security_group" "lab" {
  name        = "${local.name_pref}-sg"
  description = "Open lab SG (SSH + WireGuard + intra-SG)"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "All from self"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  ingress {
    description = "All from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH (open)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "WireGuard wg0 (UDP 51820)"
    from_port   = local.wg0_port
    to_port     = local.wg0_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "WireGuard wg1 (UDP 51821)"
    from_port   = local.wg1_port
    to_port     = local.wg1_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_pref}-sg"
  })
}

############################
# AMI (Amazon Linux 2023 x86_64)
############################
data "aws_ssm_parameter" "al2023_x86_64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
}

#data "aws_ami" "ubuntu_2404" {
#  most_recent = true
#  owners      = ["099720109477"] # Canonical
#
#  filter {
#    name   = "name"
#    values = ["ubuntu/images/hvm-ssd/ubuntu-noble-24.04-amd64-server-*"]
#  }
#
#  filter {
#    name   = "virtualization-type"
#    values = ["hvm"]
#  }
#}

data "aws_ssm_parameter" "ubuntu_2404" {
  #name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}


############################
# Common bootstrap snippet
############################
locals {
  common_bootstrap = <<-EOF
    set -euxo pipefail

    echo 'export TERM=xterm-256color' >> ~root/.bash_profile

    # Ensure root SSH key access matches exactly what you want
    install -d -m 700 /root/.ssh
    cat >/root/.ssh/authorized_keys <<'KEYS'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICef0bS7x707LF/d2CFpg2RhyT315vxI9S4cM5O5u9/J naveen@d.local
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFFR3aONIwN+TCqary68VBnFdLEY6O6UOdpTY2BEaPya naveen@c.local
KEYS
    chmod 600 /root/.ssh/authorized_keys

    cat >/etc/sysctl.d/90-baseline.conf <<'SYSCTLCONF'
    # Never use ICMP redirects
    net.ipv4.conf.all.send_redirects = 0
    net.ipv4.conf.all.accept_redirects = 0
    net.ipv4.conf.default.send_redirects = 0
    net.ipv4.conf.default.accept_redirects = 0
    net.ipv4.conf.enp39s0.accept_redirects = 0
    net.ipv4.conf.enp39s0.send_redirects = 0

    # Avoid asymmetric routing weirdness
    net.ipv4.conf.all.rp_filter = 0
    net.ipv4.conf.default.rp_filter = 0

    # Ignore bogus ICMP
    net.ipv4.icmp_ignore_bogus_error_responses = 1
SYSCTLCONF

    sysctl --system


    if grep -qi ubuntu /etc/os-release; then
      apt-get -y update && apt-get -y install iproute2 ethtool tcpdump perf-tools-unstable wireguard-tools build-essential neovim netsniff-ng
    else
      dnf -y install iproute ethtool tcpdump perf kernel-tools kernel-modules-extra wireguard-tools git make gcc libpcap libpcap-devel libnl3 libnl3-devel libnet libnet-devel flex bison ncurses ncurses-devel ncurses-static ncurses-compat-libs
      ( git clone https://github.com/borkmann/netsniff-ng && cd netsniff-ng && ./configure && make && make install; )
    fi

    cpupower frequency-set -g performance || true

    ( cd ~root/; git clone https://github.com/nnathan/aws-wg-experiment && cd aws-wg-experiment && gcc -o pflood pflood.c && mv pflood ~root/; )
  EOF
}

############################
# Instances
############################
resource "aws_instance" "source" {
  #ami                    = data.aws_ssm_parameter.ubuntu_2404.value
  ami                    = data.aws_ssm_parameter.al2023_x86_64.value
  instance_type          = var.instance_type
  key_name               = local.key_name
  subnet_id              = aws_subnet.main.id
  private_ip             = local.src_ip
  vpc_security_group_ids = [aws_security_group.lab.id]
  source_dest_check      = false

  user_data = <<-EOF
    #!/bin/bash
    ${local.common_bootstrap}

    hostnamectl set-hostname --static src

    cat >/etc/wireguard/wg0.conf <<'CONF'
    [Interface]
    Address = ${local.src_wg0_ip}
    PrivateKey = ${local.wg_a_src_priv}
    ListenPort = ${local.wg0_port}

    # Route the far-side subnet via wg0
    PostUp   = ip route replace 192.168.100.0/24 dev wg0
    PostDown = ip route del 192.168.100.0/24 dev wg0 || true

    [Peer]
    PublicKey = ${local.wg_a_mid_pub}
    AllowedIPs = 172.16.100.0/24, 192.168.100.0/24
    Endpoint = ${local.mid_ip}:${local.wg0_port}
    PersistentKeepalive = 25
    CONF

    chmod 600 /etc/wireguard/wg0.conf
    systemctl enable --now wg-quick@wg0
  EOF

  tags = merge(local.common_tags, {
    Name = "${local.name_pref}-src"
    role = "src"
  })
}

resource "aws_instance" "middle" {
  #ami                    = data.aws_ssm_parameter.ubuntu_2404.value
  ami                    = data.aws_ssm_parameter.al2023_x86_64.value
  instance_type          = var.instance_type
  key_name               = local.key_name
  subnet_id              = aws_subnet.main.id
  private_ip             = local.mid_ip
  vpc_security_group_ids = [aws_security_group.lab.id]
  source_dest_check      = false

  user_data = <<-EOF
    #!/bin/bash
    ${local.common_bootstrap}

    hostnamectl set-hostname --static mid

    # Forward between the two WireGuard interfaces
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.rp_filter=0
    sysctl -w net.ipv4.conf.default.rp_filter=0

    # wg0: mid <-> src
    cat >/etc/wireguard/wg0.conf <<'CONF'
    [Interface]
    Address = ${local.mid_wg0_ip}
    PrivateKey = ${local.wg_a_mid_priv}
    ListenPort = ${local.wg0_port}

    [Peer]
    PublicKey = ${local.wg_a_src_pub}
    AllowedIPs = 172.16.100.0/24
    Endpoint = ${local.src_ip}:${local.wg0_port}
    PersistentKeepalive = 25
    CONF

    # wg1: mid <-> snk (different UDP port)
    cat >/etc/wireguard/wg1.conf <<'CONF'
    [Interface]
    Address = ${local.mid_wg1_ip}
    PrivateKey = ${local.wg_b_mid_priv}
    ListenPort = ${local.wg1_port}

    [Peer]
    PublicKey = ${local.wg_b_snk_pub}
    AllowedIPs = 192.168.100.0/24
    Endpoint = ${local.snk_ip}:${local.wg1_port}
    PersistentKeepalive = 25
    CONF

    chmod 600 /etc/wireguard/wg0.conf /etc/wireguard/wg1.conf
    systemctl enable --now wg-quick@wg0
    systemctl enable --now wg-quick@wg1
  EOF

  tags = merge(local.common_tags, {
    Name = "${local.name_pref}-mid"
    role = "mid"
  })
}

resource "aws_instance" "sink" {
  #ami                    = data.aws_ssm_parameter.ubuntu_2404.value
  ami                    = data.aws_ssm_parameter.al2023_x86_64.value
  instance_type          = var.instance_type
  key_name               = local.key_name
  subnet_id              = aws_subnet.main.id
  private_ip             = local.snk_ip
  vpc_security_group_ids = [aws_security_group.lab.id]
  source_dest_check      = false

  user_data = <<-EOF
    #!/bin/bash
    ${local.common_bootstrap}

    hostnamectl set-hostname --static snk

    cat >/etc/wireguard/wg0.conf <<'CONF'
    [Interface]
    Address = ${local.snk_wg0_ip}
    PrivateKey = ${local.wg_b_snk_priv}
    ListenPort = ${local.wg1_port}

    # Route the far-side subnet via wg0
    PostUp   = ip route replace 172.16.100.0/24 dev wg0
    PostDown = ip route del 172.16.100.0/24 dev wg0 || true

    [Peer]
    PublicKey = ${local.wg_b_mid_pub}
    AllowedIPs = 192.168.100.0/24, 172.16.100.0/24
    Endpoint = ${local.mid_ip}:${local.wg1_port}
    PersistentKeepalive = 25
    CONF

    chmod 600 /etc/wireguard/wg0.conf
    systemctl enable --now wg-quick@wg0
  EOF

  tags = merge(local.common_tags, {
    Name = "${local.name_pref}-snk"
    role = "snk"
  })
}

############################
# Outputs
############################
output "project_uid" {
  description = "Unique ID tagging all resources in this deployment"
  value       = local.project_id
}

output "src_public_ip" { value = aws_instance.source.public_ip }
output "mid_public_ip" { value = aws_instance.middle.public_ip }
output "snk_public_ip" { value = aws_instance.sink.public_ip }

output "src_private_ip" { value = aws_instance.source.private_ip }
output "mid_private_ip" { value = aws_instance.middle.private_ip }
output "snk_private_ip" { value = aws_instance.sink.private_ip }
