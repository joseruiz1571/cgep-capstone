# CMMC: AU.L2-3.3.1, AU.L2-3.3.2 | HIPAA: 164.312(b) | SOC 2: CC7.2
package acme.cloudtrail

import future.keywords.contains
import future.keywords.if
import future.keywords.in

__rego_metadata__ := {
  "id": "ACME-CT-001",
  "title": "CloudTrail must be multi-region with log file validation",
  "controls": ["AU.L2-3.3.1", "AU.L2-3.3.2"],
  "severity": "CRITICAL",
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_cloudtrail"
  change.change.actions[_] in {"create", "update"}
  change.change.after.is_multi_region_trail != true
  msg := sprintf(
    "[AU.L2-3.3.1] CloudTrail '%v' is not multi-region. Set is_multi_region_trail = true.",
    [change.address],
  )
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_cloudtrail"
  change.change.actions[_] in {"create", "update"}
  change.change.after.enable_log_file_validation != true
  msg := sprintf(
    "[AU.L2-3.3.2] CloudTrail '%v' does not have log file validation. Set enable_log_file_validation = true.",
    [change.address],
  )
}
