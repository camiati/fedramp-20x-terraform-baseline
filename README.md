# fedramp-20x-terraform-baseline

Terraform AWS security baseline mapped to NIST SP 800-53 Rev. 5, with compliance checks on every change.

Companion to [The Grid](https://github.com/camiati/The-Grid), a reference guide to the frameworks this code implements.

## What's here

| File | Defines | Controls |
|---|---|---|
| `s3_evidence.tf` | Hardened S3 bucket for audit evidence | AC&#8209;3, AC&#8209;6, AU&#8209;2, AU&#8209;9, AU&#8209;12, CP&#8209;9, SC&#8209;7, SC&#8209;8, SC&#8209;28, SI&#8209;12 |
| `s3_access_logs.tf` | Bucket receiving the evidence bucket's access logs | AC&#8209;3, AC&#8209;6, AU&#8209;9, AU&#8209;11, SC&#8209;7, SC&#8209;8, SC&#8209;28 |
| `kms.tf` | Customer-managed key encrypting audit logs, with automatic rotation | SC&#8209;12, SC&#8209;13 |
| `cloudtrail.tf` | Multi-Region trail recording every management API call, with log file validation | AU&#8209;2, AU&#8209;3, AU&#8209;9, AU&#8209;12, SC&#8209;28 |
| `guardduty.tf` | Threat detection, including S3 Protection | SI&#8209;4, IR&#8209;4 |
| `config.tf` | Records every resource's configuration and change history | CM&#8209;2, CM&#8209;3, CM&#8209;8, CA&#8209;7 |
| `providers.tf` | Terraform and AWS provider versions | |
| [`RISK_ACCEPTANCES.md`](./RISK_ACCEPTANCES.md) | Accepted risks and planned remediations, with justifications and dates | |
| [`CLAUDE.md`](./CLAUDE.md) | Instructions for Claude Code: conventions, workflow, and hard rules | |
| [`.claude/settings.json`](./.claude/settings.json) | Enforced permission rules for Claude Code | |

Each resource is annotated in the code with the controls it supports.

## How changes are checked

Every pull request runs three checks. None of them touch AWS, and no credentials are stored.

| Check | Tool | Catches |
|---|---|---|
| Format | `terraform fmt` | Code that doesn't follow Terraform's standard style |
| Validate | `terraform validate` | Syntax errors and broken references |
| Security scan | Checkov | Security misconfigurations |

Current result: 43 passed, 0 failed, 9 skipped. Every skip is either a documented risk acceptance or a planned remediation, tracked in the [risk register](./RISK_ACCEPTANCES.md).

## Repository controls

| Control | Implementation | Maps to |
|---|---|---|
| Change management | Branch protection requires a pull request and passing checks | CM&#8209;3; SOC 2 CC8.1 |
| Supply chain | Actions pinned to commit SHAs, pinning enforced, 7-day Dependabot cooldown | SR&#8209;3; SOC 2 CC9.2 |
| Patch management | Dependabot updates for actions and the AWS provider | SI&#8209;2 |
| Risk acceptance | Checkov skip comments, a risk register, and pull request approval | RA&#8209;7 |
| Secrets | Secret scanning and push protection | IA&#8209;5(7) |
| AI tooling guardrails | Claude Code permission rules deny Terraform commands that contact AWS, all `aws` CLI commands, force-pushes, and reads of `~/.aws/`; commits and pushes require approval. Tested: denied commands are blocked before they run. | AC&#8209;6, CM&#8209;7 |

## Known gaps

- **Checkov's version is updated by hand.** It's installed inside a workflow command, which Dependabot can't see.
- **Validated, not deployed.** CI checks the code without an AWS account.
- **One account, one Region.** CloudTrail covers all Regions, but GuardDuty runs in one. Organization-wide coverage is a planned remediation.
- **No real-time alerting yet.** CloudTrail isn't yet connected to CloudWatch alarms. Also a planned remediation.

## Roadmap

1. Security Hub CSPM with the NIST SP 800-53 standard, building on AWS Config
2. CloudWatch alerting on CloudTrail events
3. A multi-account baseline with AWS Organizations
4. GitHub Actions authenticating to AWS through OIDC, with no stored keys
5. A signed container pipeline with an SBOM and build provenance
6. A machine-readable SSP in OSCAL, generated from the control annotations
