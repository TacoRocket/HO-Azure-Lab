# HO-Azure-Lab

`HO-Azure-Lab` is the Azure lab repo that lets people stand up a disposable Azure environment and
run `HO-Azure` against it.

This repo is not the runtime home for the tool.

Its public value is simple:

- download the lab repo
- stand up the Azure environment
- go get `HO-Azure` from its release page
- run the tool against the lab and see what command output is useful

Behind the scenes, this repo also contains the maintainer validation and proof workflow that keeps
the lab and tool honest.

## What This Repo Owns

This repo owns:

- live Azure validation
- viewpoint coverage
- grouped-family coverage
- proof artifacts
- demo/capture proof
- completion verification
- tool-repo blocker handoff when the issue belongs back in `HO-Azure`

This repo does not own:

- Mac, Linux, or Windows installability proof
- packaging and distribution proof
- container publishing

Those belong in `HO-Azure`.

## Operator And Maintainer Split

There are two different audiences here:

- operators or curious users
  they mainly need a straightforward way to stand up the lab environment and then a pointer to the
  released `HO-Azure` binary they should run against it
- maintainers
  they need the deeper validator, audit, artifact, and completion-verifier workflow

That means the long-term public umbrella command should stay simple:

- pick the cloud
- stand up the environment
- tell the user where to get the released tool

The current Go validation commands in this repo are still maintainer-facing bootstrap commands.
They are useful now because the validation system is being built, but they should not be mistaken
for the final public operator workflow.

## Public Goal

For a public user with no safe corporate Azure environment to test against, the intended experience
should eventually be:

- clone or download this repo
- run one straightforward environment-setup command
- let OpenTofu apply the lab
- go get the released `HO-Azure` binary from its normal release page
- run whatever commands they want against the lab and learn what output they find useful

That is the whole point of the lab:

- give people a safe place to test
- give people a realistic environment to learn against
- remove the need to point a recon tool at a risky or politically sensitive Azure environment

## Azure Setup Command

The Azure setup path is meant to stay simple.

You can use either of these:

- thin client:
  `labctl setup-environment --provider azure`
- Azure-specific path:
  `labctl setup-azure-environment`

Both land on the same Azure setup behavior.

The two main operator-facing flags are:

- `--location`
  choose the Azure region for this run
- `--cost-profile`
  choose either `default` or `lower-cost`

Those are the only setup choices the public docs should emphasize first.

Anything deeper, niche, or maintainer-oriented should stay after the main operator choices instead
of being mixed into the top of the setup story.

One deeper setup switch now stays intentionally separate:

- `--enable-azure-ml`
  turns on the Azure ML workspace lane only when you want it
  when enabled, the setup flow runs AML as a separate follow-up apply instead of folding it into
  the core OpenTofu pass
  the default lab apply leaves AML off so AML-specific naming, provisioning, or timeout problems do
  not make the main OpenTofu deploy harder to troubleshoot

If you pass nothing, the default setup is:

- `location = centralus`
- `cost-profile = default`

That means the normal first-run path uses the larger `Standard_D2s_v3` VM and VMSS sizes.

If you want the lower-cost path after quota approval, use the same command shape and change only the
cost profile and, if needed, the region:

```bash
labctl setup-environment --provider azure --cost-profile lower-cost --location centralus
```

or:

```bash
labctl setup-azure-environment --cost-profile lower-cost --location centralus
```

The setup flow writes generated OpenTofu inputs for that run and then uses those values when it
applies the lab.

If you want the Azure ML slice too, enable it explicitly:

```bash
labctl setup-azure-environment --enable-azure-ml
```

That lane is separated on purpose:

- the base lab still stands up without it
- AML follows the same general “heavier follow-up infra” idea as WAF, APIM, and AKS instead of
  being mixed into the core apply
- AML troubleshooting stays isolated when the workspace or dependent resource names drift
- maintainers can rerun or debug AML without turning the main lab apply into one larger failure

## Current Bootstrap State

The repo now has the first validation scaffold:

- a surface derivation helper
- a validation manifest schema
- a validation run-result schema
- a Go lab binary
- a manifest scaffold generator
- focused tests for the validator flow

The current bootstrap manifest is:

- [contracts/bootstrap.validation-manifest.json](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/contracts/bootstrap.validation-manifest.json)

It is intentionally an honest starter manifest, not a claim that the whole lab is already
release-ready.

Right now it tracks the full shipped `HO-Azure` surface and keeps the repo explicit about what is
still bootstrap work.

The current bootstrap target is one cohesive first gate, not a replay of the old lab's separate
phase buckets.

In plain language, that manifest now does three different things on purpose:

- marks 34 shared AzureFox-era commands plus 3 grouped families as the first covered gate
- marks manual-setup seams such as `devops`, `lighthouse`, and `cross-tenant` as explicit setup
  exceptions with recorded steps
- marks 4 newer `HO-Azure` follow-up commands and 1 follow-up family such as `app-credentials`, `azure-ml`,
  `event-grid`, `logic-apps`, and `compute-control` as tracked follow-up
  instead of pretending they are already live-gated here

## Intended Azure Lab Shape

This repo now provisions the first foundation slice of the new Azure lab, and the broader intended
resource shape is still expected to stay close to the older AzureFox lab because that shape already
proved useful validation value.

The current OpenTofu slice already includes:

- four resource groups
- the core VNet and subnets
- the workload NSG and public SSH evidence rule
- one public Linux VM
- one Linux VM scale set
- one user-assigned managed identity
- two reduced-viewpoint app registrations and service principals
- scoped `Contributor` and `Reader` assignments for those reduced viewpoints
- one public storage account
- one private storage account
- the private blob DNS zone and VNet link
- one private endpoint for the private blob path
- one public blob container for proof material
- linked ARM template and parameters blobs for deployment-history proof
- four Key Vault shapes:
  open
  deny
  private
  hybrid
- the private Key Vault DNS zone and VNet link
- private endpoints for the private and hybrid Key Vault paths
- one Linux App Service plan
- one public Linux web app with a plain-text app setting
- one empty-identity Linux web app
- one Linux function app with system-assigned and user-assigned identity plus a Key Vault-backed
  setting
- one storage account that supports the function app
- one Log Analytics workspace for the container-app slice
- one Container Apps environment
- one public Container App that reuses the lab identity
- one public Azure Container Instance that reuses the lab identity
- one dedicated App Gateway subnet
- one public WAF-backed Application Gateway
- one AKS cluster with an explicit node size
- one subscription-scope `Owner` role assignment for the lab managed identity
- one API Management service plus a public API and backend
- one Azure Container Registry
- one Azure SQL server with one database
- one Azure Automation account
- one public DNS zone
- one private DNS zone with VNet registration link

Planned lab shape:

- Four resource groups for network, data, workload, and ops resources
- One VNet with workload and private-endpoint subnets
- One public Linux VM named `vm-web-01`
  - default option:
    most Azure accounts are more likely to run cleanly with `Standard_D2s_v3`, which is roughly
    `$80/month`
  - lower-cost option:
    request quota for the `BSv2` family first, then use a smaller size such as
    `Standard_B2ts_v2`, which is roughly `$8.61/month`; when using the setup command, pass the
    location where your quota was approved and it can write that region into the OpenTofu inputs
- One snapshot named `vm-web-01-os-snap` copied from the public VM OS disk
- One Linux VM scale set named `vmss-api`
  - default option:
    same as the public VM: `Standard_D2s_v3` is the smoother known-working path
  - lower-cost option:
    same as the public VM: after `BSv2` quota approval, use the smaller family path instead
- One user-assigned managed identity named `ua-app`
- Two reduced-viewpoint app registrations plus backing service principals
  - one gives a contributor-style workload view
  - one gives a lower-visibility reader-style workload view
- Scoped role assignments for those reduced viewpoints
  - the dev viewpoint gets `Contributor` on the workload resource group
  - the lower-privilege viewpoint gets `Reader` on the workload resource group
- Two app registrations plus backing service principals for role-trust validation:
  `af-roletrust-api` and `af-roletrust-client`
- One federated identity credential on `af-roletrust-api`
- One internal app-role assignment from `af-roletrust-client` to `af-roletrust-api`
- Low-impact `Reader` RBAC assignments that make the service principals visible during lab runs
- One storage account that allows public blob access and uses firewall default action `Allow`
- One storage account with firewall default action `Deny` plus a private endpoint
- One public blob container that hosts linked ARM template and parameter artifacts
- Four Key Vaults that cover:
  public network open
  public network enabled with firewall deny
  public network plus private endpoint
  private endpoint only
- One Linux App Service with a system-assigned identity and a plain-text sensitive setting
- One Linux Function App with system-assigned plus user-assigned identity and a Key Vault-backed
  app setting
- One Event Grid subscription that routes blob-created events from the function storage account
  into the `incoming-events` storage queue
- One Linux App Service with attached identity and empty app settings
- One public Azure Container Instance with a public IP, FQDN, and user-assigned identity
- One Container Apps environment with one externally reachable Container App that reuses the lab
  identity
- One subnet-level NSG allow rule on the workload subnet so the public VM still has clear public
  ingress evidence in the network output
- One dedicated App Gateway subnet plus one public WAF-backed Application Gateway that routes to
  the public App Service
  - cost note:
    this is one of the more expensive resources in the lab, so the README should call that out
    plainly instead of letting it be an invisible surprise
- One API Management service with a system-assigned identity plus one API, one backend, and one
  named value
- One AKS cluster with a public control-plane endpoint and system-assigned identity
  - cost note:
    this is another resource where the README should be explicit that it adds real cost and should
    not silently inherit a tiny cheaper VM size just because the standalone VM and VMSS can do
    that
- One Azure Container Registry with public network access and admin user enabled
- One optional Azure ML workspace lane with:
  one workspace
  one compute target
  one blob datastore
  one Application Insights dependency
  - why this is not on by default:
    AML naming and provisioning failures can sit in slower timeout-heavy paths, so this lane stays
    explicit opt-in and separate from the core apply instead of making the base lab harder to
    troubleshoot
- One Azure SQL server with one user database
- One Azure Automation account with a system-assigned identity
- One public DNS zone plus one private DNS zone with a registration-enabled VNet link
- Three deployment-history objects:
  one succeeded subscription deployment with linked template URI
  one succeeded resource-group deployment with linked parameters URI
  one failed resource-group deployment with no outputs
- One subscription-scope `Owner` role assignment for the managed identity
- One Azure DevOps organization, project, repository, and pipeline setup
  - manual setup note:
    this is needed if you want the full `devops` command output; OpenTofu alone will not create the
    full Azure DevOps side for you
  - why this is not on by default:
    this takes extra manual setup and teardown outside the normal Azure apply flow, so it is
    treated as an intentional add-on instead of a required first-run step; if you do not turn it
    on, thinner or empty `devops` results are expected and that is not a gap in the base lab
- One cross-tenant relationship
  - manual setup note:
    this needs a second Entra tenant plus the right trust relationship back to the main lab tenant
    if you want the full `cross-tenant` command output
  - why this is not on by default:
    this depends on a second tenant and extra setup work that a casual lab user is not expected to
    build just to get started, so it stays an intentional add-on
- One Lighthouse delegated relationship
  - manual setup note:
    this needs a second Entra tenant plus the right delegated relationship back to the main lab
    tenant if you want the full `lighthouse` command output
  - why this is not on by default:
    this also depends on a second-tenant relationship and extra manual setup, so it stays an
    intentional add-on instead of a normal first-run requirement

Operator guidance should stay simple:

- default first-run path:
  one clear full-lab deployment with the smoother known-working sizes
- lower-cost path:
  same lab goal, but use the cheaper approved compute sizes once quota is available
- region selector:
  if you need a different region, pass `--location`; if you pass nothing, the setup path falls back
  to `centralus`

That is still one main lab scenario. It is not meant to become three different public workflows.

## Core Files

- [TESTS.md](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/TESTS.md)
  Plain-language validation workflow.
- [RUNS.md](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/RUNS.md)
  Plain-language run and artifact layout.
- [cmd/labctl/main.go](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/cmd/labctl/main.go)
  Primary Go entrypoint for the lab workflow.
- [internal/lab/](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/internal/lab)
  Go implementation of surface derivation, manifest scaffolding, run scaffolding, execution
  running, live payload checks, and completion verification.
- [contracts/validation-manifest.schema.json](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/contracts/validation-manifest.schema.json)
  Shape of the lab-owned manifest.
- [contracts/validation-run-result.schema.json](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/contracts/validation-run-result.schema.json)
  Shape of one validation run result.
- [canaries/devops/README.md](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/canaries/devops/README.md)
  Explains the first-party DevOps canary lane.
- [scripts/sync_devops_canaries.py](/Users/cfarley/Documents/HarrierOps/Azure/HO-Azure-Lab/scripts/sync_devops_canaries.py)
  Renders and syncs the tracked DevOps canary YAML, or renders it locally for review.

The older Python scripts are still in `scripts/` as bootstrap reference right now, but the primary
runtime path is now the Go binary.

## Plain-Language Model

There are three layers:

1. surface accounting
   Does the lab account for the full shipped `HO-Azure` surface?
2. live validation
   What does the shipped artifact actually emit against the lab, and does that payload still satisfy
   the current tool contract?
3. completion verification
   Did the full gated run finish with the required artifacts, outcomes, review topics, and tool-repo
   handoff prompts?

That last layer matters because:

- a run can be complete without being release-ready
- a run can find a tool-side blocker and still hand back a clean upstream prompt
- a run now records its own scope, so the covered gate and explicit exceptions travel with the
  run-result instead of living only in thread memory

## Maintainer Bootstrap Commands

The commands below are for the current maintainer bootstrap workflow inside this repo.

They are not the final public operator story.

Derive the live shipped surface:

```bash
go run ./cmd/labctl derive-surface --ho-azure-dir ../HO-Azure
```

Generate a starter manifest from the current shipped surface:

```bash
go run ./cmd/labctl scaffold-manifest \
  --ho-azure-dir ../HO-Azure \
  --profile truth-first-bootstrap \
  --output contracts/bootstrap.validation-manifest.json
```

Validate the manifest against the current shipped surface:

```bash
go run ./cmd/labctl validate \
  --manifest contracts/bootstrap.validation-manifest.json \
  --ho-azure-dir ../HO-Azure
```

Later, when real run results exist, add `--run-results <file>` to check completion-verifier
requirements too.

If you want the validator to print a plain-language summary instead of JSON:

```bash
go run ./cmd/labctl validate \
  --manifest contracts/bootstrap.validation-manifest.json \
  --ho-azure-dir ../HO-Azure \
  --format text
```

Scaffold a starter run directory:

```bash
go run ./cmd/labctl scaffold-run \
  --manifest contracts/bootstrap.validation-manifest.json \
  --output-dir runs/bootstrap-example
```

Run the Azure slice directly when you want the full Azure-specific Go flow:

```bash
go run ./cmd/labctl run-azure-validation \
  --manifest contracts/bootstrap.validation-manifest.json \
  --infra-dir infra \
  --output-dir runs/azure-live
```

If you want the thin umbrella entrypoint, use:

```bash
go run ./cmd/labctl run-validation \
  --provider azure \
  --manifest contracts/bootstrap.validation-manifest.json \
  --infra-dir infra \
  --output-dir runs/azure-live
```

If you want the raw Azure execution step by itself for debugging:

```bash
go run ./cmd/labctl run-azure-execution \
  --manifest contracts/bootstrap.validation-manifest.json \
  --output-dir runs/azure-live
```

If you want to inspect the raw run and apply the first contract-based live checks manually:

```bash
go run ./cmd/labctl live-validate-run \
  --run-results runs/azure-live/run-result.json \
  --write-run-results
```

## What “Done” Means Here

“Done” does not mean that the repo looks polished.

It means:

- the shipped surface is accounted for honestly
- required proof exists
- the remaining review topics are explicit
- upstream blockers get handed back cleanly
- the repo is not pretending a release gate passed when it did not
