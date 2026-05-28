# CMMC: SC.L2-3.13.8 | HIPAA: 164.312(e)(1) | SOC 2: CC6.7 | GAP-03
package acme.s3.tls

import future.keywords.contains
import future.keywords.if
import future.keywords.in

__rego_metadata__ := {
  "id": "ACME-S3-002",
  "title": "S3 bucket policy must deny non-TLS requests",
  "controls": ["SC.L2-3.13.8"],
  "severity": "HIGH",
  "gap": "GAP-03",
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket_policy"
  change.change.actions[_] in {"create", "update"}
  policy := json.unmarshal(change.change.after.policy)
  not _has_tls_deny(policy.Statement)
  msg := sprintf(
    "[SC.L2-3.13.8 | GAP-03] S3 bucket policy '%v' does not deny non-TLS requests.",
    [change.address],
  )
}

_has_tls_deny(statements) if {
  some stmt in statements
  stmt.Effect == "Deny"
  _secure_transport_condition(stmt.Condition)
}

_secure_transport_condition(condition) if {
  condition.Bool["aws:SecureTransport"] == "false"
}

_secure_transport_condition(condition) if {
  lower(condition.Bool["aws:SecureTransport"]) == "false"
}
