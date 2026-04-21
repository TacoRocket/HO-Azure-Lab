resource "azuread_application" "api" {
  display_name     = var.api_name
  owners           = [var.owner_object_id]
  sign_in_audience = "AzureADMyOrg"

  api {
    mapped_claims_enabled          = false
    requested_access_token_version = 2

    oauth2_permission_scope {
      admin_consent_description  = "Allow the lab role-trusts client app to read the proof API."
      admin_consent_display_name = "Read proof API"
      enabled                    = true
      id                         = "bf2791ee-cff1-4037-a62f-0e29f4d0411e" # gitleaks:allow
      type                       = "Admin"
      user_consent_description   = "Allow the lab role-trusts client app to read the proof API."
      user_consent_display_name  = "Read proof API"
      value                      = "Proof.Read"
    }
  }

  app_role {
    allowed_member_types = ["Application"]
    description          = "Allow a lab client application to call the proof API."
    display_name         = "Proof.Invoke"
    enabled              = true
    id                   = var.api_app_role_id
    value                = "Proof.Invoke"
  }
}

resource "azuread_service_principal" "api" {
  client_id                    = azuread_application.api.client_id
  app_role_assignment_required = false
  owners                       = [var.owner_object_id]
}

resource "azuread_application_federated_identity_credential" "api_github" {
  application_id = azuread_application.api.id
  display_name   = "github-main"
  description    = "Proof-only federated credential for HO-Azure-Lab role-trusts validation."
  issuer         = "https://token.actions.githubusercontent.com"
  audiences      = ["api://AzureADTokenExchange"]
  subject        = var.github_federated_subject
}

resource "azuread_application" "client" {
  display_name     = var.client_name
  owners           = [var.owner_object_id]
  sign_in_audience = "AzureADMyOrg"

  required_resource_access {
    resource_app_id = azuread_application.api.client_id

    resource_access {
      id   = var.api_app_role_id
      type = "Role"
    }
  }

  required_resource_access {
    resource_app_id = var.microsoft_graph_app_id

    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # gitleaks:allow
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "client" {
  client_id                    = azuread_application.client.client_id
  app_role_assignment_required = false
  owners                       = [var.owner_object_id]
}

resource "azuread_app_role_assignment" "client_to_api" {
  app_role_id         = var.api_app_role_id
  principal_object_id = azuread_service_principal.client.object_id
  resource_object_id  = azuread_service_principal.api.object_id
}

resource "azurerm_role_assignment" "api_reader" {
  scope                = var.ops_resource_group_id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.api.object_id
}

resource "azurerm_role_assignment" "client_reader" {
  scope                = var.ops_resource_group_id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.client.object_id
}
