output "role_trusts" {
  value = {
    applications = {
      api = {
        client_id    = azuread_application.api.client_id
        display_name = azuread_application.api.display_name
        object_id    = azuread_application.api.object_id
      }
      client = {
        client_id    = azuread_application.client.client_id
        display_name = azuread_application.client.display_name
        object_id    = azuread_application.client.object_id
      }
    }
    expected_trust_types = [
      "app-owner",
      "service-principal-owner",
      "federated-credential",
      "app-to-service-principal",
    ]
    federated_credential = {
      issuer  = azuread_application_federated_identity_credential.api_github.issuer
      subject = azuread_application_federated_identity_credential.api_github.subject
    }
    service_principals = {
      api = {
        display_name = azuread_service_principal.api.display_name
        object_id    = azuread_service_principal.api.object_id
      }
      client = {
        display_name = azuread_service_principal.client.display_name
        object_id    = azuread_service_principal.client.object_id
      }
    }
  }
}
