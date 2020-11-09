variable "create" {
  description = "Whether to create all resources"
  type        = bool
  default     = true
}

variable "create_sns_topic" {
  description = "Whether to create new SNS topic"
  type        = bool
  default     = true
}

variable "lambda_role" {
  description = "IAM role attached to the Lambda Function.  If this is set then a role will not be created for you."
  type        = string
  default     = ""
}

variable "lambda_function_name" {
  description = "The name of the Lambda function to create"
  type        = string
  default     = "notify_teams"
}

variable "lambda_description" {
  description = "The description of the Lambda function"
  type        = string
  default     = null
}

variable "sns_topic_name" {
  description = "The name of the SNS topic to create"
  type        = string
}

variable "sns_topic_kms_key_id" {
  description = "ARN of the KMS key used for enabling SSE on the topic"
  type        = string
  default     = ""
}

variable "teams_webhook_url" {
  description = "The URL of Teams webhook"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key used for decrypting teams webhook url"
  type        = string
  default     = ""
}

variable "log_events" {
  description = "Boolean flag to enabled/disable logging of incoming events"
  type        = bool
  default     = false
}

variable "reserved_concurrent_executions" {
  description = "The amount of reserved concurrent executions for this lambda function. A value of 0 disables lambda from being triggered and -1 removes any concurrency limitations"
  type        = number
  default     = -1
}

variable "cloudwatch_log_group_retention_in_days" {
  description = "Specifies the number of days you want to retain log events in log group for Lambda."
  type        = number
  default     = 0
}

variable "cloudwatch_log_group_kms_key_id" {
  description = "The ARN of the KMS Key to use when encrypting log data for Lambda"
  type        = string
  default     = null
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

variable "iam_role_tags" {
  description = "Additional tags for the IAM role"
  type        = map(string)
  default     = {}
}

variable "iam_role_boundary_policy_arn" {
  description = "The ARN of the policy that is used to set the permissions boundary for the role"
  type        = string
  default     = null
}

variable "iam_role_name_prefix" {
  description = "A unique role name beginning with the specified prefix"
  type        = string
  default     = "lambda"
}

variable "lambda_function_tags" {
  description = "Additional tags for the Lambda function"
  type        = map(string)
  default     = {}
}

variable "sns_topic_tags" {
  description = "Additional tags for the SNS topic"
  type        = map(string)
  default     = {}
}

variable "cloudwatch_log_group_tags" {
  description = "Additional tags for the Cloudwatch log group"
  type        = map(string)
  default     = {}
}

variable "subscription_filter_policy" {
  description = "(Optional) A valid filter policy that will be used in the subscription to filter messages seen by the target resource."
  type        = string
  default     = null
}
