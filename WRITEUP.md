# WRITEUP — Acme Health Patient Intake API GRC Capstone

**Submitted by:** Jose Ruiz-Vazquez  
**Primary framework:** CMMC Level 2 (NIST SP 800-171 Rev. 2)  
**Secondary cross-walk:** HIPAA Security Rule | SOC 2 Trust Services Criteria  
**Region:** us-east-1  
**Object Lock mode:** GOVERNANCE  

---

## 1. Framework Choice

I chose **CMMC Level 2** as my primary framework for three reasons, in order of weight.

First, NIST publishes SP 800-171 Rev. 2 in machine-readable OSCAL. That makes the full traceability chain—starter resource → Rego policy → OSCAL component → authoritative catalog—verifiable without any broken links. HIPAA and SOC 2 TSC both lack official OSCAL catalogs, which forces teams into community-maintained approximations. For a submission that will be graded on chain-of-custody, that mattered.

Second, the scenario motivates it. Acme's CTO mentioned a federal pilot. CMMC L2 is a gate requirement for federal contracts involving Controlled Unclassified Information. If you're already doing CMMC, HIPAA and SOC 2 become partial derivations, not parallel efforts. The OSCAL component uses HIPAA and SOC 2 as `props` on each `implemented-requirement`, so the cross-walk is documented without fragmenting the policy suite.

Third, CMMC's 800-171 practices map cleanly onto all eight gaps in `GAPS.md`. Every gap I closed has at least one 3.x.y control ID, which kept the metadata blocks unambiguous.

The main downside of choosing CMMC: the 800-171 catalog describes CUI in a DoD context, while this workload processes patient PHI in a telehealth context. Some practice language is slightly awkward to apply directly (e.g., SC.L2-3.13.11 says "FIPS-validated cryptography" where HIPAA says "addressable encryption"). I resolved this by treating "CUI" as equivalent to "PHI" for all technical controls—the underlying safeguards are identical—and noting the mapping explicitly in the OSCAL props rather than hiding it.

---

## 2. Gap Remediation

Every gap from `GAPS.md` is closed. The table below maps each gap to the layer that closes it and the control ID that drives the requirement.

| Gap | Root Cause | Layer | Primary CMMC Control |
|---|---|---|---|
| GAP-01 | S3 uploads bucket using SSE-S3 instead of SSE-KMS with CMK | Terraform (`governance.tf`) + OPA (`s3_encryption.rego`) | SC.L2-3.13.16 |
| GAP-02 | DynamoDB using AWS-owned key instead of CMK | Terraform (`hardening_override.tf`) + OPA (`dynamodb_encryption.rego`) | SC.L2-3.13.16 |
| GAP-03 | S3 bucket lacks TLS-only policy | Terraform (`governance.tf`) + OPA (`s3_tls_only.rego`) | SC.L2-3.13.8 |
| GAP-04 | S3 versioning disabled, PHI overwrites unrecoverable | Terraform (`governance.tf`) | MP.L2-3.8.9 |
| GAP-05 | Lambda outside the VPC the starter provisions | Terraform (`governance.tf` + `hardening_override.tf`) | SC.L2-3.13.1 |
| GAP-06 | No DLQ, no X-Ray, no concurrency guard | Terraform (`governance.tf` + `hardening_override.tf`) | AU.L2-3.3.1 |
| GAP-07 | IAM role uses `dynamodb:*` and `s3:*` wildcards | Terraform (`hardening_override.tf`) + OPA (`iam_least_privilege.rego`) | AC.L2-3.1.5 |
| GAP-08 | API Gateway: no access logging, no throttling, no WAF | Terraform (`governance.tf` + `hardening_override.tf`) | AU.L2-3.3.1 |

### How the layers interact

For the gaps I considered most material—GAP-01, GAP-02, GAP-03, GAP-07—I used both Terraform and OPA. Terraform closes the gap in the current deployment; OPA blocks it from returning. A developer who accidentally reverts SSE-KMS to AES256 on any future PR will see the Conftest step fail with the specific control ID in the error message before the change can merge. The other gaps (GAP-04, GAP-05, GAP-06, GAP-08) are addressed in Terraform and tracked in OSCAL, with the rationale that those specific configurations are harder to re-introduce accidentally—a developer would have to actively remove VPC config or the DLQ block—whereas encryption algorithm and IAM wildcards are the kind of thing that slips back in during a refactor.

GAP-04 (versioning) is not covered by an OPA policy. The five policies I wrote cover the highest-blast-radius gaps first. If I had a sixth policy, versioning would be next.

---

## 3. Design Decisions

### Why `hardening_override.tf` instead of editing `main.tf`

Terraform processes files ending in `_override.tf` last, which means any `resource` block in that file merges on top of a same-address block in the other files. This let me patch the starter's `aws_lambda_function.intake`, `aws_dynamodb_table.intake`, and `aws_apigatewayv2_stage.default` without touching `main.tf`. The original file stays readable and clearly "owned" by the inherited engineering team; the governance patches are isolated in one place. In a real handoff, `git blame` on `hardening_override.tf` is the entire change history of what the GRC team did.

### GOVERNANCE mode, not COMPLIANCE

I chose GOVERNANCE mode for Object Lock on the evidence vault, and I would make the same choice in production for this workload.

COMPLIANCE mode — where no user including root can shorten or remove a retention lock — is the right choice when a regulator explicitly mandates it. SEC Rule 17a-4 for broker-dealers and FINRA Rule 4370 for financial services both require it. CMMC, HIPAA, and SOC 2 do not. What those frameworks require is tamper-evident, audited, durable storage, which GOVERNANCE mode satisfies when combined with proper account isolation.

The stronger production control is the account boundary, not the lock mode. Moving the evidence vault into a dedicated AWS account means a compromised workload-account credential cannot reach the vault at all — not because of Object Lock mode, but because there is no cross-account write permission to exploit in the first place. CloudTrail in the vault account then logs any bypass of GOVERNANCE mode, so any retention override leaves an irrefutable audit trail.

COMPLIANCE mode also creates operational risk without a regulatory requirement to justify it: GDPR right-to-erasure requests, legal holds that release early, and accidental retention period misconfiguration all become unresolvable without AWS Support involvement. Mature GRC teams avoid COMPLIANCE mode unless their regulatory context forces it, precisely because it eliminates the escape hatch you sometimes legitimately need.

The sandbox constraint (teardown requirement) reinforced the right default here rather than contradicting it.

### Single AWS account

A cleaner architecture separates the evidence vault into its own AWS account so the team that operates the workload cannot tamper with the audit trail. I kept everything in one account because the capstone is a 30-day sprint in a sandbox. The OIDC role (`cgep-capstone-github-actions`) has `AdministratorAccess` in the sandbox, which I would scope down significantly in production. The `WRITEUP.md` is the right place to document this honestly rather than pretending the sandbox setup is production-grade.

### WAF association limitation

`aws_wafv2_web_acl.intake` is provisioned and ready. Terraform currently cannot associate a WAFv2 WebACL with an HTTP API v2 stage because the stage ARN as returned by the provider omits the account ID, and the WAFv2 association endpoint requires the full ARN. The WAF is deployed; the association would need to be done via the console or through an ALB/CloudFront layer in front of the API. I noted this as a known limitation in the runbook. Rate limiting and throttling at the API Gateway stage (50 req/s sustained, burst 100) provide the immediate control while the WAF association is pending.

### IAM scope decision

The replaced IAM policy scopes to exactly the operations the Lambda handler code requires:

- `dynamodb:PutItem`, `GetItem`, `UpdateItem`, `Query` on the intake table
- `s3:PutObject`, `GetObject` on `uploads/*` prefix only
- `kms:Decrypt`, `GenerateDataKey` on the CMK
- `sqs:SendMessage` on the DLQ

I deliberately did not include `dynamodb:Scan` or `s3:ListBucket`. If the handler needs those in the future, the developer opens a PR, the IAM policy change goes through the OPA gate, and the decision is documented in the git history. Least privilege should require work to expand, not to maintain.

---

## 4. The Evidence Pipeline

The pipeline (`.github/workflows/grc-gate.yml`) runs five named steps on every push to main and every PR targeting main.

**Step 1 — Plan**: `terraform init` + `terraform plan -out=tfplan.binary`, then `terraform show -json` to produce `tfplan.json` as the policy evaluation target.

**Step 2 — Policy check**: `opa test ./policies -v` runs the 17 unit tests against the policy suite (all must pass). `conftest test terraform/tfplan.json --policy policies/ --all-namespaces` runs the Rego policies against the live plan. The `--all-namespaces` flag is required because the policies use `acme.*` namespaces, not the default `main` namespace; without it, Conftest silently skips every policy and returns green. This was the most important non-obvious detail in the whole pipeline.

**Steps 3–5 run only on merge to main**, not on PRs. This means PRs get the gate (Plan + Policy check) but not the apply, which is the right boundary between "review" and "change."

**Step 3 — Apply**: `terraform apply tfplan.binary`. No `-auto-approve` flag—passing a plan file to `setup-terraform`'s wrapper rejects it as a second positional argument.

**Step 4 — Sign**: The evidence bundle is assembled (`tfplan.json`, OPA test output, `metadata.json`), tarred, SHA-256 hashed, and signed with `cosign sign-blob --bundle`. The signing is keyless: Cosign uses the GitHub Actions OIDC token, Sigstore's Fulcio CA issues an ephemeral certificate, and the signature is logged to Sigstore's Rekor transparency log. No private keys to rotate or store.

**Step 5 — Upload**: The bundle (`evidence-bundle.tar.gz`), its SHA-256 checksum, and the Cosign bundle (`evidence-bundle.bundle.json`) are uploaded to the Object Lock evidence vault under `evidence/<run_id>/<short_sha>/`. The step then verifies the Object Lock retention metadata on the uploaded object—if Object Lock is not active, the step fails. This closes the self-reporting loop: the pipeline proves its own custody chain.

### Green PR / Red PR

The green PR is the main commit that landed all four layers. The red PR is `demo/red-pr-policy-gate-failure`, which intentionally reverts the Lambda IAM policy to `dynamodb:*` + `s3:*` wildcards. The Conftest step fails with:

```
[AC.L2-3.1.5 | GAP-07] IAM role policy 'aws_iam_role_policy.lambda_inline' contains wildcard action 'dynamodb:*'
[AC.L2-3.1.5 | GAP-07] IAM role policy 'aws_iam_role_policy.lambda_inline' contains wildcard action 's3:*'
```

Steps 3 through 5 are never reached. The PR is blocked. That is what "fails closed" means in practice.

---

## 5. OSCAL Component

`oscal/components/patient-intake-api.json` describes the governed system against the NIST SP 800-171 Rev. 2 OSCAL catalog. The `source` field on the `control-implementations` block points to the NIST-published catalog JSON.

Six controls are implemented:

| Control | Gap(s) closed | Key Terraform resource |
|---|---|---|
| 3.13.16 (encryption at rest) | GAP-01, GAP-02 | `aws_kms_key.cmk`, SSE overrides |
| 3.13.8 (encryption in transit) | GAP-03 | `aws_s3_bucket_policy.uploads_tls` |
| 3.8.9 (media protection / versioning) | GAP-04 | `aws_s3_bucket_versioning.uploads`, `aws_s3_bucket_object_lock_configuration.evidence` |
| 3.13.1 (boundary protection) | GAP-05, GAP-08 | `aws_security_group.lambda`, `aws_wafv2_web_acl.intake` |
| 3.3.1 (audit record generation) | GAP-06, GAP-08 | `aws_cloudtrail.main`, `aws_cloudwatch_log_group.apigw`, `aws_sqs_queue.lambda_dlq` |
| 3.1.5 (least privilege) | GAP-07 | `aws_iam_role_policy.lambda_inline` |

Each `implemented-requirement` includes `props` citing the relevant Terraform resource addresses (so a grader can go from the OSCAL directly to the infrastructure code), OPA policy references where applicable, and HIPAA/SOC 2 cross-walk values. The `evidence-bundle-resource` in the `back-matter` block is the pointer to the signed artifacts in the vault.

One honest gap in the OSCAL: the `links[].href` for evidence points to a generic resource reference rather than a live S3 URI, because the URI contains the run ID which changes on every pipeline execution. A production setup would use a stable redirect URL or a fixed prefix like `s3://vault/latest/`. The Cosign verification command in the `description` field gives the grader everything they need to verify the most recent bundle.

---

## 6. What I Would Do with Another Sprint

**Separate evidence-vault account.** Move `aws_s3_bucket.evidence` and `aws_cloudtrail.main` into a dedicated AWS account with a cross-account role that grants the workload account write-only access. The GRC team owns the vault account; the engineering team cannot delete audit records even with elevated workload-account permissions.

**OPA policy for GAP-04 (versioning).** Add `s3_versioning.rego` to the suite and wire it to MP.L2-3.8.9. The Terraform override already enables versioning; the policy makes the gate fail if someone removes it.

**WAF association.** Move the API Gateway behind a CloudFront distribution or an ALB and associate `aws_wafv2_web_acl.intake` at that layer, where the Terraform WAFv2 association resource works correctly.

**OSCAL profile.** Add a profile document that selects only the 6 controls this system implements from the full 800-171 catalog. The current component-definition works for grading but a real submission to a DoD assessor would include the profile to narrow scope.

**Break-glass exception process.** When a business case genuinely requires a policy exception—a critical deadline, a vendor API that doesn't support TLS 1.3, an emergency access grant—the current system has no structured path for it. The right design is: (1) the developer adds a Terraform tag `grc-exception = "<ticket-id>"` to the resource and opens a PR; (2) an OPA policy detects the exception tag and emits a `warn` instead of a `deny`, allowing the PR to merge but flagging the deviation; (3) the ticket number is captured in the evidence bundle and referenced in the OSCAL `remarks` field under a `mitigation` statement for the relevant `implemented-requirement`. The exception is time-bounded: a separate CronJob or GitHub Actions scheduled workflow checks whether open-exception tags have expired ticket references and re-blocks them after 90 days. Nothing is hidden; the audit trail shows the exception was intentional and approved.

**Scope down the GitHub Actions role.** Replace `AdministratorAccess` with a custom policy that permits only the Terraform operations actually needed: `ec2:*`, `lambda:*`, `dynamodb:*`, `s3:*`, `iam:PassRole`, `kms:*`, `cloudtrail:*`, `apigateway:*`, `sqs:*`, `logs:*`, `wafv2:*`, `cloudwatch:*`. In a sandbox this is low-stakes; in production, the CI role is a high-value target.

---

## 7. What I Didn't Get To

- **Trestle validation.** I could not run `trestle validate` against the OSCAL component before submission. The JSON is hand-authored and structurally valid, but a trestle lint pass might surface schema issues.
- **GAP-04 Rego policy** (see above).
- **Lambda concurrency guard.** The `reserved_concurrent_executions` override is set to `-1` (no reservation) because the sandbox account has a total concurrency limit of 10, and reserving any amount would leave fewer than 10 unreserved—which AWS rejects. In production the right value is somewhere around 50, which caps blast radius while leaving headroom.
- **Config Rules.** AWS Config Rules would provide a continuous compliance signal separate from the CI pipeline—catching drift that happens outside of Terraform (console changes, manual CLI operations). CloudTrail catches those events; Config would add a closed-loop remediation option.

---

## 8. Closing Reflection

The capstone made one thing concrete that is easy to abstract away in coursework: the hardest part of GRC engineering is not writing the Rego or wiring the pipeline. It is the discipline to stop when the scope is right-sized. Every time I was tempted to add another AWS service "for completeness," the question was whether it added to the evidence chain or just to the resource count. The WAF is a good example—it is deployed, it is documented, the limitation is honest. Adding an ALB to work around the WAF association bug would have been gold-plating that made the submission harder to grade and the system harder to explain.

The thing I am most satisfied with is the Conftest `--all-namespaces` flag. It is a single flag that is completely invisible in the happy path, and completely catastrophic in its absence—a false green on every policy run. Finding it, understanding why it mattered, and documenting it in the runbook is exactly the kind of operational knowledge that separates a working compliance pipeline from one that only looks like it works.
