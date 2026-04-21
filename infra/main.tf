data "azurerm_client_config" "current" {}

data "azurerm_subscription" "current" {}

data "azuread_client_config" "current" {}

data "azuread_application_published_app_ids" "well_known" {}

resource "azurerm_resource_group" "network" {
  name     = local.resource_groups.network
  location = var.location
  tags     = local.tags
}

resource "azurerm_resource_group" "data" {
  name     = local.resource_groups.data
  location = var.location
  tags     = local.tags
}

resource "azurerm_resource_group" "workload" {
  name     = local.resource_groups.workload
  location = var.location
  tags     = local.tags
}

resource "azurerm_resource_group" "ops" {
  name     = local.resource_groups.ops
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "lab" {
  name                = format("vnet-%s", var.name_prefix)
  address_space       = ["10.42.0.0/16"]
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  tags                = local.tags
}

resource "azurerm_subnet" "workload" {
  name                 = "snet-workload"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.42.1.0/24"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                              = "snet-private-endpoints"
  resource_group_name               = azurerm_resource_group.network.name
  virtual_network_name              = azurerm_virtual_network.lab.name
  address_prefixes                  = ["10.42.2.0/24"]
  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_subnet" "application_gateway" {
  name                 = "snet-app-gateway"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.42.3.0/24"]
}

resource "azurerm_network_security_group" "workload" {
  name                = "nsg-workload"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  tags                = local.tags
}

resource "azurerm_subnet_network_security_group_association" "workload" {
  subnet_id                 = azurerm_subnet.workload.id
  network_security_group_id = azurerm_network_security_group.workload.id
}

resource "azurerm_network_security_rule" "workload_allow_ssh_internet" {
  name                        = "allow-ssh-internet"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.network.name
  network_security_group_name = azurerm_network_security_group.workload.name
}

resource "azurerm_public_ip" "vm_web" {
  name                = "pip-vm-web-01"
  location            = azurerm_resource_group.workload.location
  resource_group_name = azurerm_resource_group.workload.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "vm_web" {
  name                = "nic-web-01"
  location            = azurerm_resource_group.workload.location
  resource_group_name = azurerm_resource_group.workload.name
  tags                = local.tags

  ip_configuration {
    name                          = "ipconfig-web-01"
    subnet_id                     = azurerm_subnet.workload.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm_web.id
  }
}

resource "azurerm_user_assigned_identity" "ua_app" {
  name                = "ua-app"
  location            = azurerm_resource_group.workload.location
  resource_group_name = azurerm_resource_group.workload.name
  tags                = local.tags
}

resource "azuread_application" "viewpoint_dev" {
  display_name     = local.viewpoint_dev_name
  owners           = [data.azuread_client_config.current.object_id]
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_service_principal" "viewpoint_dev" {
  client_id                    = azuread_application.viewpoint_dev.client_id
  app_role_assignment_required = false
  owners                       = [data.azuread_client_config.current.object_id]
}

resource "azuread_application_password" "viewpoint_dev" {
  application_id = azuread_application.viewpoint_dev.id
  display_name   = "validator-dev"
  end_date       = "2099-01-01T00:00:00Z"
}

resource "azuread_application" "viewpoint_low_priv" {
  display_name     = local.viewpoint_low_priv_name
  owners           = [data.azuread_client_config.current.object_id]
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_service_principal" "viewpoint_low_priv" {
  client_id                    = azuread_application.viewpoint_low_priv.client_id
  app_role_assignment_required = false
  owners                       = [data.azuread_client_config.current.object_id]
}

resource "azuread_application_password" "viewpoint_low_priv" {
  application_id = azuread_application.viewpoint_low_priv.id
  display_name   = "validator-low-privilege"
  end_date       = "2099-01-01T00:00:00Z"
}

resource "azurerm_role_assignment" "ua_app_owner" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Owner"
  principal_id         = azurerm_user_assigned_identity.ua_app.principal_id
}

resource "azurerm_role_assignment" "viewpoint_dev_workload_contributor" {
  scope                = azurerm_resource_group.workload.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.viewpoint_dev.object_id
}

resource "azurerm_role_assignment" "viewpoint_low_priv_workload_reader" {
  scope                = azurerm_resource_group.workload.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.viewpoint_low_priv.object_id
}

module "role_trusts_canary" {
  count  = var.enable_role_trusts_canary ? 1 : 0
  source = "./canaries/role-trusts"

  owner_object_id          = data.azuread_client_config.current.object_id
  api_name                 = local.roletrust_api_name
  client_name              = local.roletrust_client_name
  api_app_role_id          = local.roletrust_api_app_role_id
  microsoft_graph_app_id   = data.azuread_application_published_app_ids.well_known.result.MicrosoftGraph
  ops_resource_group_id    = azurerm_resource_group.ops.id
  github_federated_subject = "repo:TacoRocket/HO-Azure:ref:refs/heads/main"
}

resource "azurerm_linux_virtual_machine" "vm_web" {
  name                = "vm-web-01"
  location            = azurerm_resource_group.workload.location
  resource_group_name = azurerm_resource_group.workload.name
  size                = local.effective_vm_size
  admin_username      = var.vm_admin_username
  network_interface_ids = [
    azurerm_network_interface.vm_web.id,
  ]
  disable_password_authentication = true
  tags                            = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.ua_app.id]
  }

  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = trimspace(var.ssh_public_key)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

data "azurerm_managed_disk" "vm_web_os" {
  name                = azurerm_linux_virtual_machine.vm_web.os_disk[0].name
  resource_group_name = azurerm_resource_group.workload.name
}

resource "azurerm_snapshot" "vm_web_os" {
  name                = "vm-web-01-os-snap"
  location            = azurerm_resource_group.workload.location
  resource_group_name = azurerm_resource_group.workload.name
  create_option       = "Copy"
  source_uri          = data.azurerm_managed_disk.vm_web_os.id
  tags                = local.tags
}

resource "azurerm_linux_virtual_machine_scale_set" "vmss_api" {
  name                            = "vmss-api"
  location                        = azurerm_resource_group.workload.location
  resource_group_name             = azurerm_resource_group.workload.name
  sku                             = local.effective_vmss_sku
  instances                       = 1
  admin_username                  = var.vm_admin_username
  disable_password_authentication = true
  overprovision                   = false
  tags                            = local.tags

  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = trimspace(var.ssh_public_key)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  network_interface {
    name    = "nic-vmss-api"
    primary = true

    ip_configuration {
      name      = "ipconfig-vmss-api"
      primary   = true
      subnet_id = azurerm_subnet.workload.id
    }
  }
}

resource "azurerm_storage_account" "public" {
  name                            = local.storage_public_name
  resource_group_name             = azurerm_resource_group.data.name
  location                        = azurerm_resource_group.data.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  access_tier                     = "Hot"
  public_network_access_enabled   = true
  allow_nested_items_to_be_public = true
  tags                            = local.tags
}

resource "azurerm_storage_account" "private" {
  name                            = local.storage_private_name
  resource_group_name             = azurerm_resource_group.data.name
  location                        = azurerm_resource_group.data.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  access_tier                     = "Hot"
  public_network_access_enabled   = true
  allow_nested_items_to_be_public = false
  tags                            = local.tags

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

resource "azurerm_private_dns_zone" "blob" {
  name                = local.private_blob_dns_zone_name
  resource_group_name = azurerm_resource_group.network.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                  = "blob-zone-link"
  resource_group_name   = azurerm_resource_group.network.name
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = azurerm_virtual_network.lab.id
  registration_enabled  = false
  tags                  = local.tags
}

resource "azurerm_private_endpoint" "storage_private_blob" {
  name                = "pe-${azurerm_storage_account.private.name}-blob"
  location            = azurerm_resource_group.data.location
  resource_group_name = azurerm_resource_group.data.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = local.tags

  private_service_connection {
    name                           = "psc-${azurerm_storage_account.private.name}-blob"
    private_connection_resource_id = azurerm_storage_account.private.id
    is_manual_connection           = false
    subresource_names              = ["blob"]
  }

  private_dns_zone_group {
    name                 = "blob-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }
}

resource "azurerm_storage_container" "lab_proof" {
  name                  = local.proof_container_name
  storage_account_id    = azurerm_storage_account.public.id
  container_access_type = "blob"
}

module "deployment_history_canary" {
  count  = var.enable_deployment_history_canary ? 1 : 0
  source = "./canaries/deployment-history"

  storage_account_name   = azurerm_storage_account.public.name
  storage_container_name = azurerm_storage_container.lab_proof.name
  primary_blob_endpoint  = azurerm_storage_account.public.primary_blob_endpoint
}

resource "azurerm_key_vault" "open" {
  name                          = local.keyvault_open_name
  location                      = azurerm_resource_group.data.location
  resource_group_name           = azurerm_resource_group.data.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  soft_delete_retention_days    = 7
  purge_protection_enabled      = false
  public_network_access_enabled = true
  rbac_authorization_enabled    = false
  tags                          = local.tags

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Delete",
      "Get",
      "List",
      "Purge",
      "Recover",
      "Set",
    ]
  }

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}

resource "azurerm_key_vault" "private" {
  name                          = local.keyvault_private_name
  location                      = azurerm_resource_group.data.location
  resource_group_name           = azurerm_resource_group.data.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  soft_delete_retention_days    = 7
  purge_protection_enabled      = true
  public_network_access_enabled = false
  rbac_authorization_enabled    = true
  tags                          = local.tags

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_key_vault" "deny" {
  name                          = local.keyvault_deny_name
  location                      = azurerm_resource_group.data.location
  resource_group_name           = azurerm_resource_group.data.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  soft_delete_retention_days    = 7
  purge_protection_enabled      = true
  public_network_access_enabled = true
  rbac_authorization_enabled    = true
  tags                          = local.tags

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_key_vault" "hybrid" {
  name                          = local.keyvault_hybrid_name
  location                      = azurerm_resource_group.data.location
  resource_group_name           = azurerm_resource_group.data.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  soft_delete_retention_days    = 7
  purge_protection_enabled      = true
  public_network_access_enabled = true
  rbac_authorization_enabled    = true
  tags                          = local.tags

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_private_dns_zone" "keyvault" {
  name                = local.private_keyvault_dns_zone_name
  resource_group_name = azurerm_resource_group.network.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "keyvault" {
  name                  = "keyvault-zone-link"
  resource_group_name   = azurerm_resource_group.network.name
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = azurerm_virtual_network.lab.id
  registration_enabled  = false
  tags                  = local.tags
}

resource "azurerm_private_endpoint" "keyvault_private" {
  name                = "pe-${azurerm_key_vault.private.name}-vault"
  location            = azurerm_resource_group.data.location
  resource_group_name = azurerm_resource_group.data.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = local.tags

  private_service_connection {
    name                           = "psc-${azurerm_key_vault.private.name}-vault"
    private_connection_resource_id = azurerm_key_vault.private.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }

  private_dns_zone_group {
    name                 = "keyvault-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.keyvault.id]
  }
}

resource "azurerm_private_endpoint" "keyvault_hybrid" {
  name                = "pe-${azurerm_key_vault.hybrid.name}-vault"
  location            = azurerm_resource_group.data.location
  resource_group_name = azurerm_resource_group.data.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = local.tags

  private_service_connection {
    name                           = "psc-${azurerm_key_vault.hybrid.name}-vault"
    private_connection_resource_id = azurerm_key_vault.hybrid.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }

  private_dns_zone_group {
    name                 = "keyvault-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.keyvault.id]
  }
}

resource "azurerm_key_vault_secret" "payment_api_key" {
  name         = "payment-api-key"
  value        = "HO-Azure-Lab-Only"
  key_vault_id = azurerm_key_vault.open.id
  depends_on   = [azurerm_key_vault.open]
}

resource "azurerm_service_plan" "linux" {
  name                = local.app_service_plan_name
  resource_group_name = azurerm_resource_group.workload.name
  location            = azurerm_resource_group.workload.location
  os_type             = "Linux"
  sku_name            = "B1"
  tags                = local.tags
}

resource "azurerm_storage_account" "function" {
  name                     = local.function_storage_name
  resource_group_name      = azurerm_resource_group.workload.name
  location                 = azurerm_resource_group.workload.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  access_tier              = "Hot"
  tags                     = local.tags
}

resource "azurerm_storage_queue" "event_grid" {
  name               = local.event_grid_queue_name
  storage_account_id = azurerm_storage_account.function.id
}

resource "azurerm_eventgrid_event_subscription" "function_storage_queue" {
  name  = local.event_grid_subscription_name
  scope = azurerm_storage_account.function.id

  included_event_types = ["Microsoft.Storage.BlobCreated"]
  event_delivery_schema = "EventGridSchema"

  storage_queue_endpoint {
    storage_account_id = azurerm_storage_account.function.id
    queue_name         = azurerm_storage_queue.event_grid.name
  }
}

resource "azurerm_linux_web_app" "public" {
  name                          = local.public_app_name
  resource_group_name           = azurerm_resource_group.workload.name
  location                      = azurerm_resource_group.workload.location
  service_plan_id               = azurerm_service_plan.linux.id
  public_network_access_enabled = true
  client_certificate_enabled    = false
  https_only                    = true
  tags                          = local.tags

  identity {
    type = "SystemAssigned"
  }

  site_config {
    always_on           = false
    ftps_state          = "Disabled"
    minimum_tls_version = "1.2"

    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    API_BASE_URL = "https://example.internal/api"
    DB_PASSWORD  = "HO-Azure-Lab-PlainText-Only"
  }
}

resource "azurerm_linux_web_app" "empty" {
  name                          = local.empty_app_name
  resource_group_name           = azurerm_resource_group.workload.name
  location                      = azurerm_resource_group.workload.location
  service_plan_id               = azurerm_service_plan.linux.id
  public_network_access_enabled = true
  client_certificate_enabled    = false
  https_only                    = true
  tags                          = local.tags

  identity {
    type = "SystemAssigned"
  }

  site_config {
    always_on           = false
    ftps_state          = "Disabled"
    minimum_tls_version = "1.2"

    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {}
}

resource "azurerm_linux_function_app" "orders" {
  name                            = local.function_app_name
  resource_group_name             = azurerm_resource_group.workload.name
  location                        = azurerm_resource_group.workload.location
  service_plan_id                 = azurerm_service_plan.linux.id
  storage_account_name            = azurerm_storage_account.function.name
  storage_account_access_key      = azurerm_storage_account.function.primary_access_key
  key_vault_reference_identity_id = azurerm_user_assigned_identity.ua_app.id
  functions_extension_version     = "~4"
  public_network_access_enabled   = true
  client_certificate_enabled      = false
  https_only                      = true
  tags                            = local.tags

  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.ua_app.id]
  }

  site_config {
    always_on           = true
    ftps_state          = "Disabled"
    minimum_tls_version = "1.2"

    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    PAYMENT_API_KEY = "@Microsoft.KeyVault(VaultName=${azurerm_key_vault.open.name};SecretName=${azurerm_key_vault_secret.payment_api_key.name})"
  }
}

resource "azurerm_logic_app_workflow" "inbound" {
  name                = local.logic_app_name
  location            = azurerm_resource_group.workload.location
  resource_group_name = azurerm_resource_group.workload.name
  enabled             = true
  tags                = local.tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_logic_app_trigger_http_request" "inbound" {
  name         = "manual"
  logic_app_id = azurerm_logic_app_workflow.inbound.id
  method       = "POST"
  schema = jsonencode({
    type = "object"
    properties = {
      action = {
        type = "string"
      }
    }
  })
}

resource "azurerm_logic_app_action_http" "inbound" {
  name         = "notify"
  logic_app_id = azurerm_logic_app_workflow.inbound.id
  method       = "POST"
  uri          = "https://example.org/logic-app-proof"
  body = jsonencode({
    source = "ho-azure-lab"
  })
}

resource "azurerm_log_analytics_workspace" "container_apps" {
  name                = local.log_analytics_name
  location            = azurerm_resource_group.workload.location
  resource_group_name = azurerm_resource_group.workload.name
  retention_in_days   = 30
  sku                 = "PerGB2018"
  tags                = local.tags
}

resource "azurerm_container_app_environment" "public" {
  name                       = local.container_app_env_name
  location                   = azurerm_resource_group.workload.location
  resource_group_name        = azurerm_resource_group.workload.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.container_apps.id
  tags                       = local.tags
}

resource "azurerm_container_app" "public_api" {
  name                         = local.container_app_name
  container_app_environment_id = azurerm_container_app_environment.public.id
  resource_group_name          = azurerm_resource_group.workload.name
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.ua_app.id]
  }

  ingress {
    external_enabled = true
    target_port      = 80
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "public-api"
      image  = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
      cpu    = 0.5
      memory = "1.0Gi"
    }
  }
}

resource "azurerm_container_group" "public_web" {
  name                = local.container_group_name
  location            = azurerm_resource_group.workload.location
  resource_group_name = azurerm_resource_group.workload.name
  ip_address_type     = "Public"
  dns_name_label      = local.container_group_dns_name
  os_type             = "Linux"
  restart_policy      = "Always"
  tags                = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.ua_app.id]
  }

  container {
    name   = "web"
    image  = "mcr.microsoft.com/azuredocs/aci-helloworld:latest"
    cpu    = 0.5
    memory = 1.0

    ports {
      port     = 80
      protocol = "TCP"
    }
  }

  exposed_port {
    port     = 80
    protocol = "TCP"
  }
}

resource "azurerm_public_ip" "application_gateway" {
  name                = local.app_gateway_public_ip_name
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_web_application_firewall_policy" "application_gateway" {
  name                = local.app_gateway_waf_name
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  tags                = local.tags

  policy_settings {
    enabled = true
    mode    = "Prevention"
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }
}

resource "azurerm_application_gateway" "edge" {
  name                = local.app_gateway_name
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  firewall_policy_id  = azurerm_web_application_firewall_policy.application_gateway.id
  tags                = local.tags

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101"
  }

  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 1
  }

  gateway_ip_configuration {
    name      = "gateway-ip-config"
    subnet_id = azurerm_subnet.application_gateway.id
  }

  frontend_ip_configuration {
    name                 = "public-frontend"
    public_ip_address_id = azurerm_public_ip.application_gateway.id
  }

  frontend_port {
    name = "port-80"
    port = 80
  }

  backend_address_pool {
    name  = "public-api-backend-pool"
    fqdns = [azurerm_linux_web_app.public.default_hostname]
  }

  backend_http_settings {
    name                                = "public-api-backend-https"
    cookie_based_affinity               = "Disabled"
    pick_host_name_from_backend_address = true
    port                                = 443
    protocol                            = "Https"
    request_timeout                     = 30
  }

  http_listener {
    name                           = "public-http-listener"
    frontend_ip_configuration_name = "public-frontend"
    frontend_port_name             = "port-80"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "public-api-basic-rule"
    rule_type                  = "Basic"
    http_listener_name         = "public-http-listener"
    backend_address_pool_name  = "public-api-backend-pool"
    backend_http_settings_name = "public-api-backend-https"
    priority                   = 100
  }
}

resource "azurerm_kubernetes_cluster" "main" {
  name                              = local.aks_name
  location                          = azurerm_resource_group.workload.location
  resource_group_name               = azurerm_resource_group.workload.name
  dns_prefix                        = local.aks_dns_prefix
  oidc_issuer_enabled               = true
  role_based_access_control_enabled = true
  sku_tier                          = "Free"
  tags                              = local.tags

  default_node_pool {
    name       = "system"
    node_count = 1
    vm_size    = var.aks_vm_size
  }

  identity {
    type = "SystemAssigned"
  }

  linux_profile {
    admin_username = var.vm_admin_username

    ssh_key {
      key_data = trimspace(var.ssh_public_key)
    }
  }

  network_profile {
    network_plugin    = "kubenet"
    load_balancer_sku = "standard"
  }
}

resource "azurerm_api_management" "main" {
  name                          = local.apim_name
  location                      = azurerm_resource_group.ops.location
  resource_group_name           = azurerm_resource_group.ops.name
  publisher_email               = "ho-azure-lab@example.com"
  publisher_name                = "HO-Azure Lab"
  public_network_access_enabled = true
  sku_name                      = "Consumption_0"
  tags                          = local.tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_api_management_named_value" "backend_base" {
  name                = "backend-base-url"
  api_management_name = azurerm_api_management.main.name
  resource_group_name = azurerm_resource_group.ops.name
  display_name        = "backend-base-url"
  value               = "https://${azurerm_linux_web_app.public.default_hostname}"
}

resource "azurerm_api_management_backend" "public_api" {
  name                = "public-api-backend"
  api_management_name = azurerm_api_management.main.name
  resource_group_name = azurerm_resource_group.ops.name
  protocol            = "http"
  url                 = "https://${azurerm_linux_web_app.public.default_hostname}"
}

resource "azurerm_api_management_api" "public_api" {
  name                  = "public-api"
  resource_group_name   = azurerm_resource_group.ops.name
  api_management_name   = azurerm_api_management.main.name
  revision              = "1"
  display_name          = "Public API"
  path                  = "public-api"
  protocols             = ["https"]
  service_url           = "https://${azurerm_linux_web_app.public.default_hostname}"
  subscription_required = false
}

resource "azurerm_container_registry" "main" {
  name                          = local.acr_name
  resource_group_name           = azurerm_resource_group.ops.name
  location                      = azurerm_resource_group.ops.location
  sku                           = "Basic"
  admin_enabled                 = true
  public_network_access_enabled = true
  tags                          = local.tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_application_insights" "azure_ml" {
  count               = var.enable_azure_ml ? 1 : 0
  name                = local.app_insights_name
  location            = azurerm_resource_group.ops.location
  resource_group_name = azurerm_resource_group.ops.name
  application_type    = "web"
  tags                = local.tags
}

resource "azurerm_machine_learning_workspace" "main" {
  count                         = var.enable_azure_ml ? 1 : 0
  name                          = local.azure_ml_workspace_name
  location                      = azurerm_resource_group.ops.location
  resource_group_name           = azurerm_resource_group.ops.name
  application_insights_id       = azurerm_application_insights.azure_ml[0].id
  key_vault_id                  = azurerm_key_vault.open.id
  storage_account_id            = azurerm_storage_account.public.id
  container_registry_id         = azurerm_container_registry.main.id
  public_network_access_enabled = true
  tags                          = local.tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_machine_learning_compute_cluster" "cpu" {
  count                         = var.enable_azure_ml ? 1 : 0
  name                          = local.azure_ml_compute_cluster_name
  location                      = azurerm_resource_group.ops.location
  machine_learning_workspace_id = azurerm_machine_learning_workspace.main[0].id
  vm_priority                   = "Dedicated"
  vm_size                       = local.azure_ml_compute_vm_size
  node_public_ip_enabled        = true
  ssh_public_access_enabled     = false
  tags                          = local.tags

  scale_settings {
    min_node_count                       = 0
    max_node_count                       = 1
    scale_down_nodes_after_idle_duration = "PT15M"
  }
}

resource "azurerm_machine_learning_datastore_blobstorage" "lab_proof" {
  count                = var.enable_azure_ml ? 1 : 0
  name                 = local.azure_ml_datastore_name
  workspace_id         = azurerm_machine_learning_workspace.main[0].id
  storage_container_id = "${azurerm_storage_account.public.id}/blobServices/default/containers/${azurerm_storage_container.lab_proof.name}"
  account_key          = azurerm_storage_account.public.primary_access_key
  is_default           = false
  tags                 = local.tags
}

resource "azurerm_mssql_server" "main" {
  name                          = local.sql_server_name
  resource_group_name           = azurerm_resource_group.data.name
  location                      = azurerm_resource_group.data.location
  version                       = "12.0"
  administrator_login           = local.sql_admin_login
  administrator_login_password  = local.sql_admin_password
  minimum_tls_version           = "1.2"
  public_network_access_enabled = true
  tags                          = local.tags
}

resource "azurerm_mssql_database" "main" {
  name           = local.sql_database_name
  server_id      = azurerm_mssql_server.main.id
  sku_name       = "Basic"
  max_size_gb    = 2
  zone_redundant = false
  tags           = local.tags
}

resource "azurerm_automation_account" "main" {
  name                = local.automation_account_name
  location            = azurerm_resource_group.ops.location
  resource_group_name = azurerm_resource_group.ops.name
  sku_name            = "Basic"
  tags                = local.tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_dns_zone" "public" {
  name                = local.public_dns_zone_name
  resource_group_name = azurerm_resource_group.network.name
  tags                = local.tags
}

resource "azurerm_dns_a_record" "public_vm" {
  name                = "vm-web"
  zone_name           = azurerm_dns_zone.public.name
  resource_group_name = azurerm_resource_group.network.name
  ttl                 = 300
  records             = [azurerm_public_ip.vm_web.ip_address]
}

resource "azurerm_private_dns_zone" "internal" {
  name                = local.private_dns_zone_name
  resource_group_name = azurerm_resource_group.network.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "internal" {
  name                  = "internal-zone-link"
  resource_group_name   = azurerm_resource_group.network.name
  private_dns_zone_name = azurerm_private_dns_zone.internal.name
  virtual_network_id    = azurerm_virtual_network.lab.id
  registration_enabled  = true
  tags                  = local.tags
}

resource "azurerm_private_dns_a_record" "internal_api" {
  name                = "api"
  zone_name           = azurerm_private_dns_zone.internal.name
  resource_group_name = azurerm_resource_group.network.name
  ttl                 = 300
  records             = ["10.42.1.10"]
}
