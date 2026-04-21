## HO-Azure DevOps Canary Files

This directory holds the tracked Azure DevOps YAML canary files for `HO-Azure-Lab`.

They are here to make the DevOps proof intent obvious and repeatable.

They are not claiming that this repo fully provisions every Azure DevOps prerequisite by itself.

Why this stays opt-in:

- Azure DevOps is a separate platform boundary from the normal Azure apply flow
- getting the fuller `devops` output takes extra manual setup
- tearing it back down also takes extra manual cleanup
- that means this is not left off by accident and it is not a lab gap
- it is an intentional add-on for people who want fuller DevOps coverage without forcing every
  casual lab user to build and clean up that extra world

What that means in practice:

- if you do not set up the Azure DevOps side, thinner or empty `devops` results are expected
- that does not mean the base Azure lab failed
- it means this optional extra was never turned on

Cross-platform note:

- the YAML canary files themselves are cross-platform content
- the current sync helper still uses Python as a bootstrap implementation detail, so that helper is
  not yet the ideal steady-state cross-platform runtime seam

Current boundary:

- you still need a real Azure DevOps org, project, and repo
- you still need working Azure DevOps auth
- you still need a real Azure Resource Manager service connection
- you still need a variable group
- you still need a real named target resource for the named-target canary

This repo owns:

- the tracked YAML canary layer
- the rendering logic
- the repo and pipeline sync seam where the Azure DevOps API allows it

The four canaries are:

- `/azure-pipelines.yml`
  - root YAML canary
  - proves direct root-file evidence
- `/pipelines/template-follow.yml`
  - same-repo template-follow canary
  - proves the tool can follow a local template path
- `/templates/deploy-canary.yml`
  - local template with the Azure-facing evidence
- `/pipelines/named-target.yml`
  - named-target canary
  - proves a stronger named-target join

Use the sync helper after the prerequisites exist:

```bash
python3 scripts/sync_devops_canaries.py \
  --org "https://dev.azure.com/<org-name>/" \
  --project "<project-name>" \
  --repo "<repo-name>" \
  --service-connection "<service-connection-name>" \
  --variable-group "<variable-group-name>" \
  --ops-resource-group "<ops-resource-group>" \
  --workload-resource-group "<workload-resource-group>" \
  --named-webapp "<named-webapp>"
```
