terraform {
  backend "s3" {
    bucket         = "cgep-capstone-tfstate-fed5640f"
    key            = "acme-health/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    use_path_style = false
  }
}
