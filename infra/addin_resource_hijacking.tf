variable "enable_resource_hijacking_addin" {
  description = "Enable the resource-hijacking add-in lane. This stays off by default so family-specific proof fixtures can be added separately from the base lab apply."
  type        = bool
  default     = false
}

locals {
  resource_hijacking_runbook_name  = "rb-rh-proof"
  resource_hijacking_schedule_name = "sched-rh-proof"
  resource_hijacking_webhook_name  = "wh-rh-proof"
}

resource "azurerm_automation_runbook" "resource_hijacking" {
  count                   = var.enable_resource_hijacking_addin ? 1 : 0
  name                    = local.resource_hijacking_runbook_name
  location                = azurerm_resource_group.ops.location
  resource_group_name     = azurerm_resource_group.ops.name
  automation_account_name = azurerm_automation_account.main.name
  runbook_type            = "PowerShell"
  log_verbose             = true
  log_progress            = true
  description             = "Optional resource-hijacking proof add-in runbook."
  content                 = <<-EOT
    Write-Output "HO-Azure-Lab resource-hijacking proof runbook"
  EOT
  tags                    = local.tags
}

resource "azurerm_automation_schedule" "resource_hijacking" {
  count                   = var.enable_resource_hijacking_addin ? 1 : 0
  name                    = local.resource_hijacking_schedule_name
  resource_group_name     = azurerm_resource_group.ops.name
  automation_account_name = azurerm_automation_account.main.name
  frequency               = "Day"
  interval                = 1
  timezone                = "UTC"
  start_time              = "2030-01-01T00:00:00Z"
  description             = "Optional resource-hijacking proof add-in schedule."
}

resource "azurerm_automation_job_schedule" "resource_hijacking" {
  count                   = var.enable_resource_hijacking_addin ? 1 : 0
  resource_group_name     = azurerm_resource_group.ops.name
  automation_account_name = azurerm_automation_account.main.name
  schedule_name           = azurerm_automation_schedule.resource_hijacking[0].name
  runbook_name            = azurerm_automation_runbook.resource_hijacking[0].name
}

resource "azurerm_automation_webhook" "resource_hijacking" {
  count                   = var.enable_resource_hijacking_addin ? 1 : 0
  name                    = local.resource_hijacking_webhook_name
  resource_group_name     = azurerm_resource_group.ops.name
  automation_account_name = azurerm_automation_account.main.name
  runbook_name            = azurerm_automation_runbook.resource_hijacking[0].name
  expiry_time             = "2035-01-01T00:00:00Z"
  enabled                 = true
}

output "resource_hijacking_addin" {
  description = "Resource-hijacking add-in status and resource names when that optional lane is enabled."
  value = {
    enabled       = var.enable_resource_hijacking_addin
    runbook_name  = try(azurerm_automation_runbook.resource_hijacking[0].name, null)
    schedule_name = try(azurerm_automation_schedule.resource_hijacking[0].name, null)
    webhook_name  = try(azurerm_automation_webhook.resource_hijacking[0].name, null)
  }
}
