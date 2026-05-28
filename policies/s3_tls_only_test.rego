package acme.s3.tls
import future.keywords.if

mock_pass_input := {"resource_changes": [{"address": "aws_s3_bucket_policy.uploads_tls",
  "type": "aws_s3_bucket_policy", "change": {"actions": ["create"], "after": {"policy": `{
    "Version": "2012-10-17",
    "Statement": [{"Sid": "DenyNonTLS","Effect": "Deny","Principal": "*","Action": "s3:*",
      "Resource": ["arn:aws:s3:::my-bucket","arn:aws:s3:::my-bucket/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}`}}}]}
test_pass_tls_deny_present if { count(deny) == 0 with input as mock_pass_input }

mock_fail_input := {"resource_changes": [{"address": "aws_s3_bucket_policy.uploads_tls",
  "type": "aws_s3_bucket_policy", "change": {"actions": ["create"], "after": {"policy": `{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow","Principal": "*","Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"}]}`}}}]}
test_fail_no_tls_deny if { count(deny) == 1 with input as mock_fail_input }

mock_fail_wrong_condition := {"resource_changes": [{"address": "aws_s3_bucket_policy.uploads_tls",
  "type": "aws_s3_bucket_policy", "change": {"actions": ["create"], "after": {"policy": `{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny","Principal": "*","Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]}`}}}]}
test_fail_deny_without_secure_transport if { count(deny) == 1 with input as mock_fail_wrong_condition }
