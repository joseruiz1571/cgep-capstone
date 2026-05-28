package acme.cloudtrail
import future.keywords.if

mock_pass_input := {"resource_changes": [{"address": "aws_cloudtrail.main",
  "type": "aws_cloudtrail", "change": {"actions": ["create"], "after": {
    "name": "test-trail", "s3_bucket_name": "test-bucket",
    "is_multi_region_trail": true, "enable_log_file_validation": true,
  }}}]}
test_pass_compliant_trail if { count(deny) == 0 with input as mock_pass_input }

mock_fail_single_region := {"resource_changes": [{"address": "aws_cloudtrail.main",
  "type": "aws_cloudtrail", "change": {"actions": ["create"], "after": {
    "name": "test-trail", "s3_bucket_name": "test-bucket",
    "is_multi_region_trail": false, "enable_log_file_validation": true,
  }}}]}
test_fail_single_region_trail if { count(deny) == 1 with input as mock_fail_single_region }

mock_fail_no_validation := {"resource_changes": [{"address": "aws_cloudtrail.main",
  "type": "aws_cloudtrail", "change": {"actions": ["create"], "after": {
    "name": "test-trail", "s3_bucket_name": "test-bucket",
    "is_multi_region_trail": true, "enable_log_file_validation": false,
  }}}]}
test_fail_no_log_validation if { count(deny) == 1 with input as mock_fail_no_validation }

mock_fail_both := {"resource_changes": [{"address": "aws_cloudtrail.main",
  "type": "aws_cloudtrail", "change": {"actions": ["create"], "after": {
    "name": "test-trail", "s3_bucket_name": "test-bucket",
    "is_multi_region_trail": false, "enable_log_file_validation": false,
  }}}]}
test_fail_both_violations if { count(deny) == 2 with input as mock_fail_both }
