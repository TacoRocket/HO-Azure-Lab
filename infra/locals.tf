locals {
  default_vm_size_by_profile = {
    default    = "Standard_D2s_v3"
    lower-cost = "Standard_B2ts_v2"
  }

  sanitized_prefix = substr(lower(replace(var.name_prefix, "-", "")), 0, 12)
  unique_suffix    = substr(md5("${data.azurerm_client_config.current.subscription_id}-${var.name_prefix}"), 0, 8)

  effective_vm_size  = trimspace(var.vm_size_override) != "" ? var.vm_size_override : local.default_vm_size_by_profile[var.compute_profile]
  effective_vmss_sku = trimspace(var.vmss_sku_override) != "" ? var.vmss_sku_override : local.default_vm_size_by_profile[var.compute_profile]

  viewpoint_dev_name             = "ho-viewpoint-dev-${substr(local.unique_suffix, 0, 6)}"
  viewpoint_low_priv_name        = "ho-viewpoint-lowpriv-${substr(local.unique_suffix, 0, 6)}"
  roletrust_api_name             = "ho-roletrust-api-${substr(local.unique_suffix, 0, 6)}"
  roletrust_client_name          = "ho-roletrust-client-${substr(local.unique_suffix, 0, 6)}"
  storage_public_name            = substr("st${local.sanitized_prefix}pub${local.unique_suffix}", 0, 24)
  storage_private_name           = substr("st${local.sanitized_prefix}priv${local.unique_suffix}", 0, 24)
  proof_container_name           = "labproof"
  private_blob_dns_zone_name     = "privatelink.blob.core.windows.net"
  keyvault_open_name             = substr("kvlabopen01${local.unique_suffix}", 0, 24)
  keyvault_private_name          = substr("kvlabpriv01${local.unique_suffix}", 0, 24)
  keyvault_deny_name             = substr("kvlabdeny01${local.unique_suffix}", 0, 24)
  keyvault_hybrid_name           = substr("kvlabhybrid01${local.unique_suffix}", 0, 24)
  private_keyvault_dns_zone_name = "privatelink.vaultcore.azure.net"
  function_storage_name          = substr("st${local.sanitized_prefix}func${local.unique_suffix}", 0, 24)
  event_grid_queue_name          = "incoming-events"
  event_grid_subscription_name   = "func-storage-to-queue"
  app_service_plan_name          = "asp-linux-lab"
  public_app_name                = "app-public-api-${substr(local.unique_suffix, 0, 6)}"
  empty_app_name                 = "app-empty-mi-${substr(local.unique_suffix, 0, 6)}"
  function_app_name              = "func-orders-${substr(local.unique_suffix, 0, 6)}"
  logic_app_name                 = "la-inbound-${substr(local.unique_suffix, 0, 6)}"
  persistence_logic_app_name     = "la-recurring-${substr(local.unique_suffix, 0, 6)}"
  compute_control_app_name       = "app-uami-ctrl-${substr(local.unique_suffix, 0, 6)}"
  log_analytics_name             = "log-aca-${substr(local.sanitized_prefix, 0, 8)}-${substr(local.unique_suffix, 0, 6)}"
  container_app_env_name         = "cae-ops-${substr(local.unique_suffix, 0, 6)}"
  container_app_name             = "ca-public-${substr(local.unique_suffix, 0, 6)}"
  container_group_name           = "aci-web-${substr(local.unique_suffix, 0, 6)}"
  container_group_dns_name       = "aci${substr(local.sanitized_prefix, 0, 8)}${substr(local.unique_suffix, 0, 4)}"
  app_gateway_public_ip_name     = "pip-appgw-${substr(local.unique_suffix, 0, 6)}"
  app_gateway_waf_name           = "waf-edge-${substr(local.unique_suffix, 0, 6)}"
  app_gateway_name               = "agw-edge-${substr(local.unique_suffix, 0, 6)}"
  aks_name                       = "aks-ops-${substr(local.unique_suffix, 0, 6)}"
  aks_dns_prefix                 = "aks${substr(local.sanitized_prefix, 0, 8)}${substr(local.unique_suffix, 0, 4)}"
  apim_name                      = "apim-${substr(local.sanitized_prefix, 0, 8)}-${substr(local.unique_suffix, 0, 6)}"
  acr_name                       = substr("acr${local.sanitized_prefix}${local.unique_suffix}", 0, 50)
  app_insights_name              = "appi-ops-${substr(local.unique_suffix, 0, 6)}"
  azure_ml_workspace_name        = "aml2-ops-${substr(local.unique_suffix, 0, 6)}"
  azure_ml_compute_cluster_name  = "cpu-cluster"
  azure_ml_compute_vm_size       = "Standard_A1_v2"
  azure_ml_datastore_name        = "labproofblob"
  sql_server_name                = "sql-${substr(local.sanitized_prefix, 0, 8)}-${substr(local.unique_suffix, 0, 6)}"
  sql_database_name              = "appdb"
  sql_admin_login                = "hoazureadmin"
  sql_admin_password             = "HoAzure!${substr(local.unique_suffix, 0, 4)}${substr(local.unique_suffix, 4, 4)}"
  automation_account_name        = "aa-ops-${substr(local.unique_suffix, 0, 6)}"
  deployment_path_runbook_name   = "rb-deploy-proof"
  deployment_path_schedule_name  = "sched-deploy-proof"
  deployment_path_webhook_name   = "wh-deploy-proof"
  public_dns_zone_name           = "ho-${substr(local.unique_suffix, 0, 6)}.example.net"
  private_dns_zone_name          = "ho-${substr(local.unique_suffix, 0, 6)}.internal"

  resource_groups = {
    network  = format("rg-%s-network", var.name_prefix)
    data     = format("rg-%s-data", var.name_prefix)
    workload = format("rg-%s-workload", var.name_prefix)
    ops      = format("rg-%s-ops", var.name_prefix)
  }

  tags = {
    project     = "ho-azure-lab"
    managed_by  = "opentofu"
    environment = "lab"
  }

  roletrust_api_app_role_id = "8d9f6db5-7727-4f80-aef0-60bf3777ee61" # gitleaks:allow
}
