output "deployment_history" {
  value = {
    subscription_deployment_name   = local.deployment_names.subscription
    resource_group_deployment_name = local.deployment_names.resource_group
    failed_deployment_name         = local.deployment_names.failed
    subscription_template_uri      = "${var.primary_blob_endpoint}${var.storage_container_name}/${azurerm_storage_blob.sub_template.name}"
    resource_group_parameters_uri  = "${var.primary_blob_endpoint}${var.storage_container_name}/${azurerm_storage_blob.rg_parameters.name}"
    proof_container_name           = var.storage_container_name
  }
}
