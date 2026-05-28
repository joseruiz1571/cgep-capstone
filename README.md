# cgep-capstone — Acme Health Patient Intake API

**Primary framework:** CMMC Level 2 (NIST SP 800-171 Rev. 2)  
**Cross-walk:** HIPAA Security Rule | SOC 2 Trust Services Criteria  
**Closes:** All 8 gaps in `GAPS.md`

See [`WRITEUP.md`](WRITEUP.md) for full design decisions, gap mapping, and trade-offs.

---

## Grader verification

### 1. OPA policy tests (17/17)

```bash
opa test ./policies -v
```

Expected: `PASS: 17/17`

### 2. Conftest policy gate

```bash
# Generate a plan first (requires AWS credentials + backend configured):
cd terraform
terraform init -input=false
terraform plan -out=tfplan.binary -lock=false -input=false
terraform show -json tfplan.binary > tfplan.json
cd ..

# Run the gate — must pass clean:
conftest test terraform/tfplan.json \
  --policy policies/ \
  --output table \
  --all-namespaces
```

Expected: all policies pass (0 failures).

### 3. API smoke test

```bash
make test
```

Expected:
```json
{
    "submission_id": "...",
    "status": "received"
}
```

### 4. Verify a signed evidence bundle

```bash
# Download the latest bundle from the evidence vault:
EVIDENCE_BUCKET=$(cd terraform && terraform output -raw evidence_bucket)

BUNDLE_KEY=$(aws s3 ls s3://${EVIDENCE_BUCKET}/evidence/ --recursive \
  | sort | tail -1 | awk '{print $4}' | sed 's/evidence-bundle\.bundle\.json//')

aws s3 cp "s3://${EVIDENCE_BUCKET}/${BUNDLE_KEY}evidence-bundle.tar.gz"        ./verify-bundle.tar.gz
aws s3 cp "s3://${EVIDENCE_BUCKET}/${BUNDLE_KEY}evidence-bundle.tar.gz.sha256" ./verify-bundle.tar.gz.sha256
aws s3 cp "s3://${EVIDENCE_BUCKET}/${BUNDLE_KEY}evidence-bundle.bundle.json"   ./verify-bundle.bundle.json

# Verify Cosign signature (Sigstore / keyless):
cosign verify-blob verify-bundle.tar.gz \
  --bundle verify-bundle.bundle.json \
  --certificate-identity-regexp "https://github.com/.*cgep-capstone" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify SHA-256 integrity:
sha256sum -c verify-bundle.tar.gz.sha256
```

Expected: `Verified OK` from Cosign, then `verify-bundle.tar.gz: OK` from sha256sum.

### 5. Verify Object Lock retention

```bash
EVIDENCE_BUCKET=$(cd terraform && terraform output -raw evidence_bucket)

LATEST_KEY=$(aws s3 ls s3://${EVIDENCE_BUCKET}/evidence/ --recursive \
  | grep "evidence-bundle\.tar\.gz$" | sort | tail -1 | awk '{print $4}')

aws s3api head-object \
  --bucket "${EVIDENCE_BUCKET}" \
  --key "${LATEST_KEY}" \
  --query '{ObjectLockMode: ObjectLockMode, RetainUntil: ObjectLockRetainUntilDate}' \
  --output table
```

Expected: `GOVERNANCE` mode, retain-until date approximately 1 year from the pipeline run.

### 6. Pipeline history (green + red)

Green PR (all 5 steps pass): the commit that landed all four layers on `main`.  
Red PR (blocked at Step 2): branch `demo/red-pr-policy-gate-failure` — IAM wildcards trigger `ACME-IAM-001`.

```bash
gh run list --limit 10
```

---

## Layout

```
cgep-capstone/
├── WRITEUP.md                          # design decisions, gap mapping, trade-offs
├── GAPS.md                             # 8 named gaps from the starter
├── FRAMEWORKS.md                       # HIPAA / SOC 2 / CMMC mapping primer
├── policies/
│   ├── s3_encryption.rego              # GAP-01 | SC.L2-3.13.16
│   ├── s3_encryption_test.rego
│   ├── dynamodb_encryption.rego        # GAP-02 | SC.L2-3.13.16
│   ├── dynamodb_encryption_test.rego
│   ├── s3_tls_only.rego                # GAP-03 | SC.L2-3.13.8
│   ├── s3_tls_only_test.rego
│   ├── iam_least_privilege.rego        # GAP-07 | AC.L2-3.1.5
│   ├── iam_least_privilege_test.rego
│   ├── cloudtrail_enabled.rego         # AU.L2-3.3.1 / AU.L2-3.3.2
│   └── cloudtrail_enabled_test.rego
├── terraform/
│   ├── main.tf                         # starter (unmodified)
│   ├── variables.tf                    # starter (unmodified)
│   ├── outputs.tf                      # starter (unmodified)
│   ├── backend.tf                      # S3 remote state
│   ├── governance.tf                   # KMS CMK, evidence vault, CloudTrail, VPC, DLQ, WAF
│   ├── hardening_override.tf           # patches starter resources (DynamoDB, Lambda, IAM, API GW)
│   └── lambda/handler.py
├── .github/workflows/grc-gate.yml      # 5-step pipeline: plan → gate → apply → sign → upload
├── oscal/components/
│   └── patient-intake-api.json         # NIST SP 800-171 Rev. 2 component definition
└── test/
    └── intake.sh
```

---

## Teardown

```bash
cd terraform
terraform destroy -auto-approve
```
