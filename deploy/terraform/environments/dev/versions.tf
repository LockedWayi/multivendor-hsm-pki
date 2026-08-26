terraform {
  required_version = ">= 1.6.0"

  required_providers {
    hostinger = {
      source  = "hostinger/hostinger"
      version = "~> 0.1.22"
    }
  }
}
