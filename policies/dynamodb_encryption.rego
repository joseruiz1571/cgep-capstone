# CMMC: SC.L2-3.13.16 | HIPAA: 164.312(a)(2)(iv) | SOC 2: CC6.1 | GAP-02
package acme.dynamodb.encryption

import future.keywords.contains
import future.keywords.if
import future.keywords.in

__rego_metadata__ := {
  "id": "ACME-DDB-001",
  "title": "DynamoDB must have SSE with customer-managed KMS key",
  "controls": ["SC.L2-3.13.16"],
  "severity": "HIGH",
  "gap": "GAP-02",
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_dynamodb_table"
  change.change.actions[_] in {"create", "update"}
  not _sse_enabled(change.change.after)
  msg := sprintf(
    "[SC.L2-3.13.16 | GAP-02] DynamoDB table '%v' does not have SSE enabled with a CMK.",
    [change.address],
  )
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_dynamodb_table"
  change.change.actions[_] in {"create", "update"}
  sse := change.change.after.server_side_encryption[_]
  sse.enabled == true
  not sse.kms_key_arn
  msg := sprintf(
    "[SC.L2-3.13.16 | GAP-02] DynamoDB table '%v' has SSE but no customer kms_key_arn.",
    [change.address],
  )
}

_sse_enabled(after) if { after.server_side_encryption[_].enabled == true }
