package acme.dynamodb.encryption
import future.keywords.if

mock_pass_input := {"resource_changes": [{"address": "aws_dynamodb_table.intake",
  "type": "aws_dynamodb_table", "change": {"actions": ["create"], "after": {
    "name": "test-table", "billing_mode": "PAY_PER_REQUEST", "hash_key": "id",
    "server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123:key/abc"}],
  }}}]}
test_pass_dynamodb_with_cmk if { count(deny) == 0 with input as mock_pass_input }

mock_fail_no_sse_input := {"resource_changes": [{"address": "aws_dynamodb_table.intake",
  "type": "aws_dynamodb_table", "change": {"actions": ["create"], "after": {
    "name": "test-table", "billing_mode": "PAY_PER_REQUEST", "hash_key": "id",
  }}}]}
test_fail_no_sse_block if { count(deny) == 1 with input as mock_fail_no_sse_input }

mock_fail_no_cmk_input := {"resource_changes": [{"address": "aws_dynamodb_table.intake",
  "type": "aws_dynamodb_table", "change": {"actions": ["create"], "after": {
    "name": "test-table", "billing_mode": "PAY_PER_REQUEST", "hash_key": "id",
    "server_side_encryption": [{"enabled": true}],
  }}}]}
test_fail_sse_without_cmk_arn if { count(deny) == 1 with input as mock_fail_no_cmk_input }
