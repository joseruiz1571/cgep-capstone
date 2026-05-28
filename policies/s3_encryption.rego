# CMMC: SC.L2-3.13.16 | HIPAA: 164.312(a)(2)(iv) | SOC 2: CC6.1 | GAP-01
package acme.s3.encryption

import future.keywords.contains
import future.keywords.if
import future.keywords.in

__rego_metadata__ := {
  "id": "ACME-S3-001",
  "title": "S3 SSE must use aws:kms with customer-managed key",
  "controls": ["SC.L2-3.13.16"],
  "severity": "HIGH",
  "gap": "GAP-01",
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket_server_side_encryption_configuration"
  change.change.actions[_] in {"create", "update"}
  some rule in change.change.after.rule
  algo := rule.apply_server_side_encryption_by_default[_].sse_algorithm
  algo != "aws:kms"
  msg := sprintf(
    "[SC.L2-3.13.16 | GAP-01] %v uses SSE algorithm '%v'. Must use 'aws:kms' with a customer-managed key.",
    [change.address, algo],
  )
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket_server_side_encryption_configuration"
  change.change.actions[_] in {"create", "update"}
  some rule in change.change.after.rule
  defaults := rule.apply_server_side_encryption_by_default[_]
  defaults.sse_algorithm == "aws:kms"
  not _has_cmk_arn(defaults)
  msg := sprintf(
    "[SC.L2-3.13.16 | GAP-01] %v uses aws:kms but no kms_master_key_id. Provide a customer CMK ARN.",
    [change.address],
  )
}

_has_cmk_arn(defaults) if {
  defaults.kms_master_key_id != null
  defaults.kms_master_key_id != ""
}
