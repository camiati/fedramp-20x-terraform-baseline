# CLAUDE.md

Context for Claude Code when working in this repository.

## What this repo is

A public portfolio project: a Terraform AWS security baseline mapped to NIST SP 800-53 Rev. 5. It is **validated in CI, never deployed**. There is no AWS account for this project.

## Hard rules

- **Never run Terraform commands that contact AWS** (`plan`, `apply`, `destroy`, `import`, `state`). These are also blocked in `.claude/settings.json`. This machine has AWS credentials for an employer's account; they must not be used.
- **Never run `aws` CLI commands** or read `~/.aws/`.
- **Safe local commands:** `terraform fmt`, `terraform init -backend=false`, `terraform validate`, and Checkov.
- **Never commit to `main`.** Main is protected; all changes go through a branch and pull request.
- **Never put secrets, account IDs, or employer details in any file.**

## Conventions

- **Control annotations:** every resource has a comment above it naming the NIST SP 800-53 controls it supports, e.g. `# SC-28: encrypt everything at rest with AWS KMS.`
- **ARNs** use `local.partition` so code works in GovCloud (`aws-us-gov`).
- **Actions are pinned to full commit SHAs** with the version in a comment: `uses: actions/checkout@<sha> # v7.0.1`. Pinning is enforced in repo settings.
- **Checkov findings are fixed or documented, never ignored.** A skip goes inside the resource as `#checkov:skip=CHECK_ID:justification. See RISK_ACCEPTANCES.md.` and gets a row in `RISK_ACCEPTANCES.md`:
  - **Current acceptances** for risks deliberately accepted
  - **Planned remediations** for real gaps with a planned fix (POA&M-style)
- **README stays current:** new files get a row in "What's here"; the Checkov result line and Known gaps are updated with each change.
- **Formatting:** run `terraform fmt` before committing. CI fails on unformatted code.

## Workflow

1. Create a branch.
2. Make the change, with control annotations.
3. Run `terraform fmt`, `terraform validate`, and Checkov locally.
4. Triage any Checkov findings with the owner before adding skips. Skips are risk decisions, not shortcuts.
5. Update the README and risk register.
6. Commit with a descriptive message, push, and open a pull request.

## Working with the owner

- Go **one step at a time**, and explain what a change does before making it.
- Ask before running commands or committing.
- Be direct and concise. Confirm facts rather than guessing; say so when unsure.

## Roadmap

1. CloudWatch alerting on CloudTrail events (planned remediation CKV2_AWS_10)
2. Multi-account baseline with AWS Organizations (planned remediation CKV2_AWS_3)
3. GitHub Actions authenticating to AWS through OIDC
4. Signed container pipeline with SBOM and build provenance
5. OSCAL SSP generated from control annotations