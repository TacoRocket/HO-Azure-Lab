variable "location" {
  description = "Azure region for the lab."
  type        = string
  default     = "centralus"
}

variable "name_prefix" {
  description = "Short prefix used in globally unique resource names."
  type        = string
  default     = "hoazurelab"

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{3,18}$", var.name_prefix))
    error_message = "name_prefix must be 3-18 characters and contain only letters, numbers, or hyphens."
  }
}

variable "vm_admin_username" {
  description = "Admin username for the lab VM and VM scale set."
  type        = string
  default     = "hoazure"
}

variable "ssh_public_key" {
  description = "RSA SSH public key used for lab compute."
  type        = string
  nullable    = false

  validation {
    condition     = length(trimspace(var.ssh_public_key)) > 0
    error_message = "ssh_public_key must be provided."
  }

  validation {
    condition     = startswith(trimspace(var.ssh_public_key), "ssh-rsa ")
    error_message = "Azure requires an RSA SSH public key for this lab."
  }
}

variable "compute_profile" {
  description = "Compute cost profile for the VM and VMSS baseline. Use default first, then switch to lower-cost after quota approval."
  type        = string
  default     = "default"

  validation {
    condition     = contains(["default", "lower-cost"], var.compute_profile)
    error_message = "compute_profile must be either default or lower-cost."
  }
}

variable "vm_size_override" {
  description = "Optional override for the public VM size. Leave empty to use the size implied by compute_profile."
  type        = string
  default     = ""
}

variable "vmss_sku_override" {
  description = "Optional override for the VM scale set size. Leave empty to use the size implied by compute_profile."
  type        = string
  default     = ""
}

variable "aks_vm_size" {
  description = "AKS system-node VM size. Keep this explicit so the smaller VM or VMSS cost path does not silently change AKS."
  type        = string
  default     = "Standard_D2s_v3"
}

variable "enable_role_trusts_canary" {
  description = "Enable the role-trust proof canary objects. This stays on by default because it is a low-friction same-Azure truth canary."
  type        = bool
  default     = true
}

variable "enable_deployment_history_canary" {
  description = "Enable the deployment-history resource canaries. This stays on by default because it is a low-friction same-Azure truth canary."
  type        = bool
  default     = true
}

variable "enable_azure_ml" {
  description = "Enable the Azure ML workspace, compute, and datastore lane. This stays off by default so AML-specific provisioning failures are isolated from the main lab apply."
  type        = bool
  default     = false
}
