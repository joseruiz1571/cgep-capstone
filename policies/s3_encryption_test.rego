package acme.s3.encryption
import future.keywords.if

mock_pass_input := {"resource_changes": [{
  "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
  "type": "aws_s3_bucket_server_side_encryption_configuration",
  "change": {"actions": ["create"], "after": {"rule": [{
    "apply_server_side_encryption_by_default": [{
      "sse_algorithm": "aws:kms",
      "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123",
    }],
    "bucket_key_enabled": true,
  }]}},
}]}

test_pass_sse_kms_with_cmk if { count(deny) == 0 with input as mock_pass_input }

mock_fail_aes256_input := {"resource_changes": [{
  "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
  "type": "aws_s3_bucket_server_side_encryption_configuration",
  "change": {"actions": ["create"], "after": {"rule": [{
    "apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}],
    "bucket_key_enabled": false,
  }]}},
}]}

test_fail_sse_s3_aes256 if { count(deny) == 1 with input as mock_fail_aes256_input }

mock_fail_no_cmk_input := {"resource_changes": [{
  "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
  "type": "aws_s3_bucket_server_side_encryption_configuration",
  "change": {"actions": ["create"], "after": {"rule": [{
    "apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}],
    "bucket_key_enabled": true,
  }]}},
}]}

test_fail_kms_without_cmk_arn if { count(deny) == 1 with input as mock_fail_no_cmk_input }
