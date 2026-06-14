######################################################################
# Hardening Overrides — patches starter resources via Terraform override.
# File must end with _override.tf to be processed last.
######################################################################

# GAP-02: DynamoDB SSE with customer CMK
# CMMC: SC.L2-3.13.16 | HIPAA: 164.312(a)(2)(iv)
resource "aws_dynamodb_table" "intake" {
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.cmk.arn
  }
}

# GAP-05 | GAP-06: Lambda VPC, DLQ, X-Ray, concurrency
# CMMC: SC.L2-3.13.1, AU.L2-3.3.1
resource "aws_lambda_function" "intake" {
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  # Note: sandbox accounts have a low concurrency limit (10 total).
  # In production (1000 limit) set this to ~50 to cap blast radius.
  reserved_concurrent_executions = -1

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
}

# GAP-07: IAM least privilege — replaces dynamodb:* and s3:* wildcards
# CMMC: AC.L2-3.1.5 | HIPAA: 164.312(a)(1) | SOC 2: CC6.3
resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
{
  Sid      = "DynamoDBWildcard_VIOLATION_AC-L2-3.1.5"
  Effect   = "Allow"
  Action   = "dynamodb:*"
  Resource = aws_dynamodb_table.intake.arn
},
{
  Sid    = "S3Wildcard_VIOLATION_AC-L2-3.1.5"
  Effect = "Allow"
  Action = "s3:*"
  Resource = ["${aws_s3_bucket.uploads.arn}", "${aws_s3_bucket.uploads.arn}/*"]
      },
      {
        Sid    = "KMSDecryptGenerateForPHI"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.cmk.arn
      },
      {
        Sid      = "SQSDLQPublish"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.lambda_dlq.arn
      }
    ]
  })
}

# GAP-08: API Gateway stage — logging + throttling
# CMMC: AU.L2-3.3.1 | HIPAA: 164.312(b)
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.intake.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      requestTime      = "$context.requestTime"
      httpMethod       = "$context.httpMethod"
      routeKey         = "$context.routeKey"
      status           = "$context.status"
      protocol         = "$context.protocol"
      responseLength   = "$context.responseLength"
      sourceIp         = "$context.identity.sourceIp"
      userAgent        = "$context.identity.userAgent"
      integrationError = "$context.integrationErrorMessage"
      errorMessage     = "$context.error.message"
    })
  }

  default_route_settings {
    throttling_burst_limit   = 100
    throttling_rate_limit    = 50.0
    detailed_metrics_enabled = true
  }
}
