variable "cluster_name" {
  default = "packet-k8s-cluster"
}

variable "node_count"{
  default = 2
}

variable "facility"{
  default = "ewr1"
}

variable "server_type"{
  default = "c2.medium.x86"
}

variable "operating_system"{
  default = "ubuntu_16_04"
}

variable "project_id"{
}

variable "api_key"{
}

variable "OS_AUTH_URL"{
}

variable "OS_REGION_NAME"{
}

variable "OS_USERNAME"{
}

variable "OS_PASSWORD"{
}

variable "OS_TENANT_NAME"{
}

variable "PF9_Account_Endpoint"{
}
