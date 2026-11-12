terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  backend "s3" {
    bucket         = "sentinelops-terraform-state"
    key            = "sandbox/terraform.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "sentinelops-terraform-locks"
    encrypt        = true
    profile        = null
  }
}
