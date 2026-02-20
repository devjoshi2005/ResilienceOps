terraform{
    required_version = ">=1.5.0"
    required_providers {
      aws={
        source = "hashicorp/aws"
        version = "~>5.0"
      }
      azurerm={
        source = "hashicorp/azurerm"
        version = "~>3.0"
      }
    }
}
provider "aws" {
  shared_credentials_files = ["~/.aws/credentials"] 
  region = "ap-east-1" #Hong Kong
}
