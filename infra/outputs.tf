output "compute_profile" {
  description = "Chosen compute profile for the lab VM and VMSS baseline."
  value       = var.compute_profile
}

output "subscription_id" {
  description = "Azure subscription ID used for the lab deployment."
  value       = data.azurerm_subscription.current.subscription_id
}

output "tenant_id" {
  description = "Azure tenant ID used for the lab deployment."
  value       = data.azurerm_client_config.current.tenant_id
}

output "resource_group_names" {
  description = "Resource groups created for the lab."
  value = {
    network  = azurerm_resource_group.network.name
    data     = azurerm_resource_group.data.name
    workload = azurerm_resource_group.workload.name
    ops      = azurerm_resource_group.ops.name
  }
}

output "effective_vm_size" {
  description = "Effective public VM size after profile selection and overrides."
  value       = local.effective_vm_size
}

output "effective_vmss_sku" {
  description = "Effective VMSS size after profile selection and overrides."
  value       = local.effective_vmss_sku
}

output "aks_vm_size" {
  description = "Explicit AKS node size."
  value       = var.aks_vm_size
}

output "vm_web_name" {
  description = "Public VM workload name."
  value       = azurerm_linux_virtual_machine.vm_web.name
}

output "vm_web_public_ip" {
  description = "Public IP assigned to the public VM."
  value       = azurerm_public_ip.vm_web.ip_address
}

output "vmss_api_name" {
  description = "Internal VM scale set name."
  value       = azurerm_linux_virtual_machine_scale_set.vmss_api.name
}

output "managed_identity" {
  description = "Managed identity details for the public VM workload."
  value = {
    id           = azurerm_user_assigned_identity.ua_app.id
    name         = azurerm_user_assigned_identity.ua_app.name
    principal_id = azurerm_user_assigned_identity.ua_app.principal_id
    client_id    = azurerm_user_assigned_identity.ua_app.client_id
    owner_scope  = azurerm_role_assignment.ua_app_owner.scope
  }
}

output "viewpoints" {
  description = "Viewpoint identities and scoped role posture for the lab."
  value = {
    admin = {
      expected_visibility = "subscription-owner"
      principal_type      = "ManagedIdentity"
      principal_name      = azurerm_user_assigned_identity.ua_app.name
      scopes = [
        {
          role_name  = azurerm_role_assignment.ua_app_owner.role_definition_name
          scope_kind = "subscription"
          scope_name = data.azurerm_subscription.current.display_name
        },
      ]
    }
    dev = {
      display_name        = azuread_application.viewpoint_dev.display_name
      expected_visibility = "scoped-workload-contributor"
      forbidden_roles     = ["Owner"]
      principal_object_id = azuread_service_principal.viewpoint_dev.object_id
      principal_type      = "ServicePrincipal"
      scopes = [
        {
          role_name  = azurerm_role_assignment.viewpoint_dev_workload_contributor.role_definition_name
          scope_kind = "resource-group"
          scope_name = azurerm_resource_group.workload.name
        },
      ]
    }
    lower_privilege = {
      display_name        = azuread_application.viewpoint_low_priv.display_name
      expected_visibility = "constrained-workload-reader"
      forbidden_roles     = ["Owner", "Contributor"]
      principal_object_id = azuread_service_principal.viewpoint_low_priv.object_id
      principal_type      = "ServicePrincipal"
      scopes = [
        {
          role_name  = azurerm_role_assignment.viewpoint_low_priv_workload_reader.role_definition_name
          scope_kind = "resource-group"
          scope_name = azurerm_resource_group.workload.name
        },
      ]
    }
  }
}

output "validation_viewpoints" {
  description = "Sensitive credentials and login metadata for reduced-viewpoint validation."
  sensitive   = true
  value = {
    dev = {
      client_id           = azuread_application.viewpoint_dev.client_id
      client_secret       = azuread_application_password.viewpoint_dev.value
      display_name        = azuread_application.viewpoint_dev.display_name
      principal_object_id = azuread_service_principal.viewpoint_dev.object_id
      subscription_id     = data.azurerm_subscription.current.subscription_id
      tenant_id           = data.azurerm_client_config.current.tenant_id
      viewpoint           = "dev"
    }
    lower_privilege = {
      client_id           = azuread_application.viewpoint_low_priv.client_id
      client_secret       = azuread_application_password.viewpoint_low_priv.value
      display_name        = azuread_application.viewpoint_low_priv.display_name
      principal_object_id = azuread_service_principal.viewpoint_low_priv.object_id
      subscription_id     = data.azurerm_subscription.current.subscription_id
      tenant_id           = data.azurerm_client_config.current.tenant_id
      viewpoint           = "lower-privilege"
    }
  }
}

output "role_trusts" {
  description = "Role-trust proof objects created for the lab."
  value       = var.enable_role_trusts_canary ? module.role_trusts_canary[0].role_trusts : null
}

output "storage_account_names" {
  description = "Storage accounts created for the lab."
  value = {
    public  = azurerm_storage_account.public.name
    private = azurerm_storage_account.private.name
  }
}

output "proof_container_name" {
  description = "Public blob container used for proof artifacts."
  value       = azurerm_storage_container.lab_proof.name
}

output "deployment_history" {
  description = "Deployment-history resource canaries created for arm-deployments proof."
  value       = var.enable_deployment_history_canary ? module.deployment_history_canary[0].deployment_history : null
}

output "private_blob_dns_zone_name" {
  description = "Private DNS zone used for the private blob endpoint."
  value       = azurerm_private_dns_zone.blob.name
}

output "key_vault_names" {
  description = "Key Vaults created for the lab."
  value = {
    open    = azurerm_key_vault.open.name
    deny    = azurerm_key_vault.deny.name
    private = azurerm_key_vault.private.name
    hybrid  = azurerm_key_vault.hybrid.name
  }
}

output "private_keyvault_dns_zone_name" {
  description = "Private DNS zone used for the private Key Vault endpoint."
  value       = azurerm_private_dns_zone.keyvault.name
}

output "app_service_names" {
  description = "App Service resources created for the lab."
  value = {
    public_web = azurerm_linux_web_app.public.name
    empty_web  = azurerm_linux_web_app.empty.name
    function   = azurerm_linux_function_app.orders.name
    plan       = azurerm_service_plan.linux.name
  }
}

output "function_storage_name" {
  description = "Storage account used by the Linux function app."
  value       = azurerm_storage_account.function.name
}

output "logic_app_name" {
  description = "Logic App workflow created for the lab."
  value       = azurerm_logic_app_workflow.inbound.name
}

output "logic_app_validation_workflows" {
  description = "Logic App workflow names used by validation lanes."
  value = {
    inbound_request_identity = azurerm_logic_app_workflow.inbound.name
    persistence_recurrence   = try(azurerm_logic_app_workflow.persistence[0].name, null)
    no_identity_recurrence   = try(azurerm_logic_app_workflow.no_identity[0].name, null)
    queue_api_connection     = try(azurerm_api_connection.queue[0].name, null)
  }
}

output "container_resources" {
  description = "Container App and Container Instance resources created for the lab."
  value = {
    log_analytics_workspace = azurerm_log_analytics_workspace.container_apps.name
    container_app_env       = azurerm_container_app_environment.public.name
    container_app           = azurerm_container_app.public_api.name
    container_group         = azurerm_container_group.public_web.name
    container_group_fqdn    = azurerm_container_group.public_web.fqdn
  }
}

output "application_gateway" {
  description = "Application Gateway and WAF policy created for the lab."
  value = {
    application_gateway = azurerm_application_gateway.edge.name
    public_ip           = azurerm_public_ip.application_gateway.ip_address
    waf_policy          = azurerm_web_application_firewall_policy.application_gateway.name
  }
}

output "aks_cluster" {
  description = "AKS cluster created for the lab."
  value = {
    name        = azurerm_kubernetes_cluster.main.name
    fqdn        = azurerm_kubernetes_cluster.main.fqdn
    node_size   = var.aks_vm_size
    oidc_issuer = azurerm_kubernetes_cluster.main.oidc_issuer_url
  }
}

output "api_management_name" {
  description = "API Management service created for the lab."
  value       = azurerm_api_management.main.name
}

output "container_registry_name" {
  description = "Container Registry created for the lab."
  value       = azurerm_container_registry.main.name
}

output "azure_ml" {
  description = "Azure ML lane status and resource names when that optional lane is enabled."
  value = {
    enabled              = var.enable_azure_ml
    workspace_name       = try(azurerm_machine_learning_workspace.main[0].name, null)
    compute_cluster_name = try(azurerm_machine_learning_compute_cluster.cpu[0].name, null)
    datastore_name       = try(azurerm_machine_learning_datastore_blobstorage.lab_proof[0].name, null)
  }
}

output "deployment_path_addin" {
  description = "Deployment-path add-in status and resource names when that optional lane is enabled."
  value = {
    enabled       = var.enable_deployment_path_addin
    runbook_name  = try(azurerm_automation_runbook.deployment_path[0].name, null)
    schedule_name = try(azurerm_automation_schedule.deployment_path[0].name, null)
    webhook_name  = try(azurerm_automation_webhook.deployment_path[0].name, null)
  }
}

output "compute_control_addin" {
  description = "Compute-control add-in status and resource names when that optional lane is enabled."
  value = {
    enabled  = var.enable_compute_control_addin
    app_name = try(azurerm_linux_web_app.compute_control[0].name, null)
  }
}

output "persistence_addin" {
  description = "Persistence add-in status and resource names when that optional lane is enabled."
  value = {
    enabled                    = var.enable_persistence_addin
    logic_app_name             = try(azurerm_logic_app_workflow.persistence[0].name, null)
    trigger_name               = try(azurerm_logic_app_trigger_recurrence.persistence[0].name, null)
    action_name                = try(azurerm_logic_app_action_http.persistence[0].name, null)
    connector_action_name      = try(azurerm_logic_app_action_custom.persistence_queue_connector[0].name, null)
    queue_api_connection_name  = try(azurerm_api_connection.queue[0].name, null)
    no_identity_logic_app_name = try(azurerm_logic_app_workflow.no_identity[0].name, null)
  }
}

output "sql_resources" {
  description = "SQL Server and database created for the lab."
  value = {
    server   = azurerm_mssql_server.main.name
    database = azurerm_mssql_database.main.name
  }
}

output "automation_account_name" {
  description = "Automation account created for the lab."
  value       = azurerm_automation_account.main.name
}

output "dns_zones" {
  description = "Public and private DNS zones created for the lab."
  value = {
    public  = azurerm_dns_zone.public.name
    private = azurerm_private_dns_zone.internal.name
  }
}
