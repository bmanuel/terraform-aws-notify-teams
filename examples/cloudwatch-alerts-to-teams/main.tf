provider "aws" {
  region = "eu-west-1"
}

resource "aws_kms_key" "this" {
  description = "KMS key for notify-teams test"
}

# Encrypt the URL, storing encryption here will show it in logs and in tfstate
# https://www.terraform.io/docs/state/sensitive-data.html
resource "aws_kms_ciphertext" "teams_url" {
  plaintext = "https://hooks.teams.com/services/AAA/BBB/CCC"
  key_id    = aws_kms_key.this.arn
}

module "notify_teams" {
  source = "../../"

  for_each = toset([
    "develop",
    "release",
    "test",
  ])

  sns_topic_name = "teams-topic"

  lambda_function_name = "notify_teams_${each.value}"

  teams_webhook_url = aws_kms_ciphertext.teams_url.ciphertext_blob

  kms_key_arn = aws_kms_key.this.arn

  lambda_description = "Lambda function which sends notifications to Teams"
  log_events         = true

  tags = {
    Name = "cloudwatch-alerts-to-teams"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "NotifyTeamsDuration"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "60"
  statistic           = "Average"
  threshold           = "5000"
  alarm_description   = "Duration of notifying teams exceeds threshold"

  alarm_actions = [module.notify_teams["develop"].this_teams_topic_arn]

  dimensions = {
    FunctionName = module.notify_teams["develop"].notify_teams_lambda_function_name
  }
}
