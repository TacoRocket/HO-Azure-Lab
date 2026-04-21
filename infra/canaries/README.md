# Infra Canaries

This folder holds proof-only resource canaries for the Azure lab.

These are not the normal baseline lab resources.

They exist to make specific validation surfaces easier to prove without pretending those proof-only
objects are part of the everyday operator story.

Practical rule:

- base infrastructure should model what a reasonable Azure environment normally has
- a canary should only exist when we need an extra proof object to make a specific logic path show
  up honestly and repeatably
- if the base lab genuinely depends on a resource, it should stay in the base infra flow instead of
  being hidden under `canaries/`

Current canary folders:

- `role-trusts/`
  proof-only Entra application, service-principal, federated-credential, and app-role-assignment
  objects used to keep `role-trusts` validation honest
- `deployment-history/`
  linked ARM template artifacts used so the Go setup flow can stamp real Azure deployment-history
  records for `arm-deployments`
