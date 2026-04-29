variable "enable_exfil_addin" {
  description = "Enable the exfil add-in lane. This stays off by default so telemetry-routing and sink proof fixtures are explicit."
  type        = bool
  default     = false
}

locals {
  exfil_eventhub_namespace_name = "evh-exfil-${substr(local.sanitized_prefix, 0, 8)}-${substr(local.unique_suffix, 0, 6)}"
  exfil_eventhub_name           = "telemetry-route"
  exfil_consumer_group_name     = "blue-team-review"
  exfil_eventhub_rule_name      = "diagnostic-send"

  exfil_public_app_log_categories = var.enable_exfil_addin ? slice(
    sort(data.azurerm_monitor_diagnostic_categories.exfil_public_app[0].log_category_types),
    0,
    min(2, length(data.azurerm_monitor_diagnostic_categories.exfil_public_app[0].log_category_types)),
  ) : []
  exfil_public_app_metric_categories = var.enable_exfil_addin ? slice(
    sort(data.azurerm_monitor_diagnostic_categories.exfil_public_app[0].metrics),
    0,
    min(1, length(data.azurerm_monitor_diagnostic_categories.exfil_public_app[0].metrics)),
  ) : []
}

data "azurerm_monitor_diagnostic_categories" "exfil_public_app" {
  count       = var.enable_exfil_addin ? 1 : 0
  resource_id = azurerm_linux_web_app.public.id
}

resource "azurerm_eventhub_namespace" "exfil" {
  count               = var.enable_exfil_addin ? 1 : 0
  name                = local.exfil_eventhub_namespace_name
  location            = azurerm_resource_group.ops.location
  resource_group_name = azurerm_resource_group.ops.name
  sku                 = "Standard"
  capacity            = 1
  minimum_tls_version = "1.2"
  tags                = local.tags
}

resource "azurerm_eventhub" "exfil_telemetry" {
  count             = var.enable_exfil_addin ? 1 : 0
  name              = local.exfil_eventhub_name
  namespace_id      = azurerm_eventhub_namespace.exfil[0].id
  partition_count   = 2
  message_retention = 1
  status            = "Active"
}

resource "azurerm_eventhub_consumer_group" "exfil_review" {
  count               = var.enable_exfil_addin ? 1 : 0
  name                = local.exfil_consumer_group_name
  namespace_name      = azurerm_eventhub_namespace.exfil[0].name
  eventhub_name       = azurerm_eventhub.exfil_telemetry[0].name
  resource_group_name = azurerm_resource_group.ops.name
  user_metadata       = "HO-Azure exfil validation review group"
}

resource "azurerm_eventhub_namespace_authorization_rule" "exfil_diagnostic_send" {
  count               = var.enable_exfil_addin ? 1 : 0
  name                = local.exfil_eventhub_rule_name
  namespace_name      = azurerm_eventhub_namespace.exfil[0].name
  resource_group_name = azurerm_resource_group.ops.name
  listen              = false
  send                = true
  manage              = false
}

resource "azurerm_monitor_diagnostic_setting" "exfil_public_app_loganalytics" {
  count                      = var.enable_exfil_addin ? 1 : 0
  name                       = "exfil-app-to-loganalytics"
  target_resource_id         = azurerm_linux_web_app.public.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.container_apps.id

  dynamic "enabled_log" {
    for_each = local.exfil_public_app_log_categories
    content {
      category = enabled_log.value
    }
  }

  dynamic "enabled_metric" {
    for_each = local.exfil_public_app_metric_categories
    content {
      category = enabled_metric.value
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "exfil_public_app_eventhub" {
  count                          = var.enable_exfil_addin ? 1 : 0
  name                           = "exfil-app-to-eventhub"
  target_resource_id             = azurerm_linux_web_app.public.id
  eventhub_name                  = azurerm_eventhub.exfil_telemetry[0].name
  eventhub_authorization_rule_id = azurerm_eventhub_namespace_authorization_rule.exfil_diagnostic_send[0].id

  dynamic "enabled_log" {
    for_each = local.exfil_public_app_log_categories
    content {
      category = enabled_log.value
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "exfil_public_app_storage" {
  count              = var.enable_exfil_addin ? 1 : 0
  name               = "exfil-app-to-storage"
  target_resource_id = azurerm_linux_web_app.public.id
  storage_account_id = azurerm_storage_account.public.id

  dynamic "enabled_log" {
    for_each = local.exfil_public_app_log_categories
    content {
      category = enabled_log.value
    }
  }

  dynamic "enabled_metric" {
    for_each = local.exfil_public_app_metric_categories
    content {
      category = enabled_metric.value
    }
  }
}

output "exfil_addin" {
  description = "Exfil add-in status and telemetry-route proof resources when that optional lane is enabled."
  value = {
    enabled                 = var.enable_exfil_addin
    eventhub_namespace_name = try(azurerm_eventhub_namespace.exfil[0].name, null)
    eventhub_name           = try(azurerm_eventhub.exfil_telemetry[0].name, null)
    consumer_group_name     = try(azurerm_eventhub_consumer_group.exfil_review[0].name, null)
    diagnostic_settings = {
      public_app_loganalytics = try(azurerm_monitor_diagnostic_setting.exfil_public_app_loganalytics[0].name, null)
      public_app_eventhub     = try(azurerm_monitor_diagnostic_setting.exfil_public_app_eventhub[0].name, null)
      public_app_storage      = try(azurerm_monitor_diagnostic_setting.exfil_public_app_storage[0].name, null)
    }
    no_diagnostic_settings_resource = azurerm_linux_web_app.empty.name
  }
}
