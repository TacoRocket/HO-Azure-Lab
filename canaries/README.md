# Repo Canaries

This folder holds non-infrastructure canary material for `HO-Azure-Lab`.

These canaries are intentional proof extras.

They help the lab prove a specific behavior or truth boundary, but they are not the same thing as
the normal baseline Azure resources in `infra/`.

Practical rule:

- the base lab should reflect what a reasonable environment normally has
- a repo-level canary belongs here when we need extra evidence to make a logic path show up
  honestly and repeatably
- the Azure DevOps YAML canaries are the model example: some enterprises will not have a useful
  tracked pipeline shape by default, so the canaries give the validator something explicit to prove

Current canary folders:

- `devops/`
  tracked Azure DevOps YAML canaries plus their operator-facing notes
