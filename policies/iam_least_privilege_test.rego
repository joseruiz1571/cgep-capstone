package acme.iam.leastprivilege
import future.keywords.if

mock_pass_input := {"resource_changes": [{"address": "aws_iam_role_policy.lambda_inline",
  "type": "aws_iam_role_policy", "change": {"actions": ["create"], "after": {"policy": `{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
      "Action": ["dynamodb:PutItem","dynamodb:GetItem"],
      "Resource": "arn:aws:dynamodb:us-east-1:123:table/test"}]}`}}}]}
test_pass_scoped_actions if { count(deny) == 0 with input as mock_pass_input }

mock_fail_dynamodb_input := {"resource_changes": [{"address": "aws_iam_role_policy.lambda_inline",
  "type": "aws_iam_role_policy", "change": {"actions": ["create"], "after": {"policy": `{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow","Action": "dynamodb:*",
      "Resource": "arn:aws:dynamodb:us-east-1:123:table/test"}]}`}}}]}
test_fail_dynamodb_star if { count(deny) == 1 with input as mock_fail_dynamodb_input }

mock_fail_s3_input := {"resource_changes": [{"address": "aws_iam_role_policy.lambda_inline",
  "type": "aws_iam_role_policy", "change": {"actions": ["create"], "after": {"policy": `{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow","Action": ["s3:*","dynamodb:PutItem"],"Resource": "*"}]}`}}}]}
test_fail_s3_star if { count(deny) >= 1 with input as mock_fail_s3_input }

mock_fail_all_input := {"resource_changes": [{"address": "aws_iam_role_policy.lambda_inline",
  "type": "aws_iam_role_policy", "change": {"actions": ["create"], "after": {"policy": `{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow","Action": "*","Resource": "*"}]}`}}}]}
test_fail_all_actions_star if { count(deny) >= 1 with input as mock_fail_all_input }
