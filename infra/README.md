# Infra Bootstrap

This directory is the OpenTofu bootstrap root for `HO-Azure-Lab`.

OpenTofu-first matters here on purpose:

- this repo should stay as open-source-friendly as possible
- Terraform-compatible HCL is fine when it keeps the files readable and familiar
- but the default assumption should still be “can OpenTofu do this cleanly?”
- if a future infra slice needs something Terraform-specific, that should be documented plainly with
  the reason instead of being treated as an invisible default

Today it sets the first real OpenTofu foundation slice for the Azure lab:

- resource groups
- core network
- public VM
- VM scale set
- managed identity
- reduced-viewpoint app registrations and service principals
- scoped reduced-viewpoint role assignments
- public and private storage
- private blob endpoint wiring
- four Key Vault visibility and network shapes
- private Key Vault endpoint wiring
- one Linux App Service plan
- two Linux web apps
- one Linux function app with a Key Vault-backed setting
- one supporting function storage account
- one Log Analytics workspace
- one Container Apps environment
- one public Container App
- one public Azure Container Instance
- one dedicated App Gateway subnet
- one public WAF-backed Application Gateway
- one AKS cluster
- one subscription-scope `Owner` role assignment for the lab managed identity
- one API Management service
- one Container Registry
- one SQL server with one database
- one Automation account
- public and private DNS zones

Canary-layout rule:

- proof-only infrastructure extras should live under `infra/canaries/`
- the current optional canaries are:
  - `infra/canaries/role-trusts/`
  - `infra/canaries/deployment-history/`
- the actual Azure deployment-history records are created by the Go setup flow so that step stays
  cross-platform instead of depending on a Unix-only helper script
- canaries are optional by design:
  - the base lab should still stand up cleanly without them
  - same-Azure low-friction canaries can still be enabled by default when they make the normal lab
    more truthful without adding a separate platform dependency
  - higher-friction or external canaries should still stay explicit opt-in choices
  - once a canary is worth keeping, its removal or cleanup path should be documented just as
    clearly as its setup path so users are not left guessing how to back it out

It also keeps the cost-aware variable model for the rest of the lab.

The intended operator shape is:

- one OpenTofu variable model underneath
- one setup command in the Go binary that chooses values such as region and cost profile
- one generated tfvars file for that run
- if no region or cost flags are passed, the setup path should still generate a working default
  input set using `centralus` and the default compute profile
- optional proof canaries should stay explicit setup choices instead of sneaking into the base
  default unless they are same-Azure low-friction truth canaries that we intentionally keep on by
  default
- slower or failure-prone platform slices that are useful but not required for the base lab should
  also stay explicit opt-in setup lanes
- when the operator teardown path is added later, keep the naming simple:
  - `destroy environment`
  - `destroy environment all`

Second-phase user note:

- the core OpenTofu apply stays focused on the base Azure environment
- human-user viewpoints should be attempted as a separate second-phase setup step instead of being
  wired into the same hard-fail OpenTofu apply path
- the current Go setup flow now has an explicit optional second-phase lane for that:
  - `--enable-human-user-viewpoints`
- when enabled, that second phase:
  - tries to create one lab `HOdev` user and one lab `HOuser` user with randomized suffixes
  - generates strong random passwords for that environment
  - writes those sensitive credentials to a generated local file
  - warns instead of failing the whole lab if tenant policy blocks the automated user flow

Follow-up infra note:

- the core OpenTofu apply now excludes a few heavier downstream surfaces so the majority of the lab
  can still stand up and validate if one of those slices is flaky
- the Go setup flow still auto-runs them right after core apply as best-effort follow-up
  infrastructure:
  - API Management
  - AKS
  - WAF/Application Gateway
- if one of those follow-up slices fails, setup should warn clearly instead of pretending the
  surface landed or blocking the rest of the lab from being usable

Azure ML note:

- the Azure ML workspace lane is now opt-in through generated tfvars and `labctl --enable-azure-ml`
- when enabled, the Go setup flow applies it as a separate follow-up infrastructure pass instead of
  folding it into the core apply
- keep it outside the base apply by default because AML naming mistakes or slow provider behavior
  can be harder to troubleshoot when they fail inside the same main OpenTofu pass
- when AML is enabled, it should still use the same shared storage, key-vault, and container
  registry truth that the command validator expects

Optional proof add-in note:

- three richer follow-up proof lanes now use that same explicit second-pass pattern:
  - `--enable-deployment-path-addin`
  - `--enable-compute-control-addin`
  - `--enable-persistence-addin`
- when enabled, the Go setup flow applies them as their own follow-up infrastructure passes instead
  of folding them into the core lab apply
- keep them opt-in by default because they enrich grouped-family proof more than they help the
  first-run base lab
- the intended proof shape for each lane is:
  - deployment-path:
    Automation runbook + schedule + webhook
  - compute-control:
    one cleaner user-assigned-identity App Service workload
  - persistence:
    one recurrence-driven Logic App path
- if one of those add-in passes fails, setup should warn clearly and leave the base lab intact

That keeps the operator path simpler than shipping multiple near-duplicate tfvars files.

The important rule is:

- the public VM and VMSS can follow a cheaper compute path after quota approval
- AKS must stay explicit so a cheaper VM or VMSS choice does not silently change the AKS shape
- the lab should also bake in the default three-viewpoint story as much as it can:
  - admin stays the broad owner-style lane
  - dev gets a scoped workload `Contributor` view
  - lower-privilege gets a scoped workload `Reader` view

Current compute profiles:

- `default`
  - uses `Standard_D2s_v3` for the VM and VMSS baseline
  - smoother first-run path for the current subscription shape
- `lower-cost`
  - uses `Standard_B2ts_v2` for the VM and VMSS baseline
  - intended for use after the `BSv2` family quota is approved and exposed

This is still one lab scenario.

It is not a separate partial-lab mode.

Region and quota rule:

- region stays an input, not a hardcoded subscription assumption
- if someone gets their quota approved in a different region, the setup command should write that
  location into the generated tfvars for the run
- quota approval is regional, so changing location means checking quota for that region too

Generated-input note:

- the setup flow writes JSON tfvars, so ordinary whitespace drift is not the main risk here
- a later follow-up should still add an explicit generated-input verification step in the setup path
  so the operator gets a cleaner failure if the written values are incomplete or inconsistent
