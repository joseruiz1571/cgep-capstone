# CMMC: AC.L2-3.1.5 | HIPAA: 164.312(a)(1) | SOC 2: CC6.3 | GAP-07
package acme.iam.leastprivilege

import future.keywords.contains
import future.keywords.if
import future.keywords.in

__rego_metadata__ := {
  "id": "ACME-IAM-001",
  "title": "IAM role policies must not use wildcard actions",
  "controls": ["AC.L2-3.1.5", "AC.L2-3.1.6"],
  "severity": "HIGH",
  "gap": "GAP-07",
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_iam_role_policy"
  change.change.actions[_] in {"create", "update"}
  policy := json.unmarshal(change.change.after.policy)
  some stmt in policy.Statement
  stmt.Effect == "Allow"
  some action in _get_actions(stmt)
  _is_wildcard_service_action(action)
  msg := sprintf(
    "[AC.L2-3.1.5 | GAP-07] IAM role policy '%v' contains wildcard action '%v'. Scope to minimum required actions.",
    [change.address, action],
  )
}

deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_iam_role_policy"
  change.change.actions[_] in {"create", "update"}
  policy := json.unmarshal(change.change.after.policy)
  some stmt in policy.Statement
  stmt.Effect == "Allow"
  some action in _get_actions(stmt)
  action == "*"
  msg := sprintf(
    "[AC.L2-3.1.5 | GAP-07] IAM role policy '%v' uses '*' (all actions). Never acceptable for PHI stores.",
    [change.address],
  )
}

_is_wildcard_service_action(action) if { endswith(action, ":*") }

_get_actions(stmt) := stmt.Action if { is_array(stmt.Action) }
_get_actions(stmt) := [stmt.Action] if { is_string(stmt.Action) }
