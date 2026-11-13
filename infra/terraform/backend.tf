terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  # Local-only state is intentionally used in this repository until a live AWS sandbox
  # is explicitly authorized. The S3 backend is reserved for an approved deployment
  # workflow and is not initialized here, which keeps local validation reproducible
  # without requiring AWS credentials or a live environment.
  backend "local" {}
}
