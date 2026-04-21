locals {
  sub_template_hash = substr(filemd5("${path.module}/arm-templates/sub-foundation.json"), 0, 8)
  rg_parameters_hash = substr(filemd5("${path.module}/arm-templates/kv-secrets.parameters.json"), 0, 8)

  sub_template_blob_name  = "templates/sub-foundation-${local.sub_template_hash}.json"
  rg_parameters_blob_name = "parameters/kv-secrets-${local.rg_parameters_hash}.parameters.json"

  deployment_names = {
    subscription   = "sub-foundation"
    resource_group = "kv-secrets"
    failed         = "app-failed"
  }
}

resource "azurerm_storage_blob" "sub_template" {
  name                   = local.sub_template_blob_name
  storage_account_name   = var.storage_account_name
  storage_container_name = var.storage_container_name
  type                   = "Block"
  source                 = "${path.module}/arm-templates/sub-foundation.json"
}

resource "azurerm_storage_blob" "rg_parameters" {
  name                   = local.rg_parameters_blob_name
  storage_account_name   = var.storage_account_name
  storage_container_name = var.storage_container_name
  type                   = "Block"
  source                 = "${path.module}/arm-templates/kv-secrets.parameters.json"
}
