terraform {
  required_version = ">= 1.4.0"
}

resource "aws_security_group" "open_all" {
  name        = "sample-open-all"
  description = "Deliberately insecure sample"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
