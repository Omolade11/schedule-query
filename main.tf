provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "schedule_query_role" {
  name               = "schedule_query"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
  statement {
    sid     = "AssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::377582181475:user/redshift-trial"]
    }
  }
}



resource "aws_iam_policy" "schedule_query_policy" {
  name   = "schedule_query_policy"
  policy = data.aws_iam_policy_document.combined_policies.json
}

data "aws_iam_policy_document" "combined_policies" {
  source_policy_documents = [
    data.aws_iam_policy_document.event_bridge_policy.json,
    data.aws_iam_policy_document.create_service_api_policy.json,
    data.aws_iam_policy_document.create_service_eventbridge_policy.json,
    data.aws_iam_policy_document.secrets_manager_access_policy.json,
    data.aws_iam_policy_document.iam_pass_role_policy.json,
    data.aws_iam_policy_document.iam_pass_role_scheduler_policy.json,
    data.aws_iam_policy_document.secrets_manager_permission_policy.json,
    data.aws_iam_policy_document.get_credential_api_policy.json,
    data.aws_iam_policy_document.get_serverless_policy.json,
    data.aws_iam_policy_document.deny_create_api_policy.json,
    data.aws_iam_policy_document.service_linked_role_policy_data.json,
    data.aws_iam_policy_document.redshift_policy.json,
    data.aws_iam_policy_document.service_linked_role_policy.json,
    data.aws_iam_policy_document.data_api_permissions_policy.json,
    data.aws_iam_policy_document.secrets_manager_list_policy.json,
    data.aws_iam_policy_document.secrets_manager_create_policy.json
  ]
}


data "aws_iam_policy_document" "event_bridge_policy" {
  statement {
    sid = "EventBridgeActions"

    actions = [
      "events:*",
      "schemas:*",
      "scheduler:*"
    ]

    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "create_service_api_policy" {

  statement {
    sid = "IAMCreateServiceLinkedRoleForApiDestinations"

    actions = [
      "iam:CreateServiceLinkedRole",
    ]

    resources = [
      "arn:aws:iam::*:role/aws-service-role/AmazonEventBridgeApiDestinationsServiceRolePolicy",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"

      values = [
        "apidestinations.events.amazonaws.com",
      ]
    }
  }
}

data "aws_iam_policy_document" "create_service_eventbridge_policy" {

  statement {
    sid = "IAMCreateServiceLinkedRoleForAmazonEventBridgeSchemas"

    actions = [
      "iam:CreateServiceLinkedRole",
    ]

    resources = [
      "arn:aws:iam::*:role/aws-service-role/schemas.amazonaws.com/AWSServiceRoleForSchemas",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"

      values = [
        "schemas.amazonaws.com",
      ]
    }
  }
}

data "aws_iam_policy_document" "secrets_manager_access_policy" {

  statement {
    sid = "SecretsManagerAccessForApiDestinations"

    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:UpdateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue"
    ]

    resources = [
      "arn:aws:secretsmanager:*:*:secret:events!*",
    ]
  }
}


data "aws_iam_policy_document" "iam_pass_role_policy" {

  statement {
    sid = "IAMPassRoleAccessForEventBridge"

    actions = [
      "iam:PassRole",
    ]

    resources = [
      "arn:aws:iam::*:role/*",
    ]
    condition {
      test     = "StringLike"
      variable = "iam:PassedToService"

      values = [
        "events.amazonaws.com",
      ]
    }
  }
}

data "aws_iam_policy_document" "iam_pass_role_scheduler_policy" {

  statement {
    sid = "IAMPassRoleAccessForScheduler"

    actions = [
      "iam:PassRole",
    ]

    resources = [
      "arn:aws:iam::*:role/*",
    ]
    condition {
      test     = "StringLike"
      variable = "iam:PassedToService"

      values = [
        "scheduler.amazonaws.com",
      ]
    }
  }
}


data "aws_iam_policy_document" "secrets_manager_permission_policy" {

  statement {
    sid = "SecretsManagerPermissions"

    actions = [
      "secretsmanager:GetSecretValue",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringLike"
      variable = "secretsmanager:ResourceTag/RedshiftDataFullAccess"

      values = [
        "*",
      ]
    }
  }
}

data "aws_iam_policy_document" "get_credential_api_policy" {

  statement {
    sid = "GetCredentialsForAPIUser"

    actions = [
      "redshift:GetClusterCredentials",

    ]

    resources = [
      "arn:aws:redshift:*:*:dbname:*/*",
      "arn:aws:redshift:*:*:dbuser:*/redshift_data_api_user"
    ]
  }
}

data "aws_iam_policy_document" "get_serverless_policy" {

  statement {
    sid = "GetCredentialsForServerless"

    actions = [
      "redshift-serverless:GetCredentials",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/RedshiftDataFullAccess"

      values = [
        "*",
      ]
    }
  }
}

data "aws_iam_policy_document" "deny_create_api_policy" {

  statement {
    sid    = "DenyCreateAPIUser"
    effect = "Deny"
    actions = [
      "redshift:CreateClusterUser",

    ]

    resources = [
      "arn:aws:redshift:*:*:dbuser:*/redshift_data_api_user",
    ]
  }
}

data "aws_iam_policy_document" "service_linked_role_policy_data" {

  statement {
    sid = "ServiceLinkedRole"

    actions = [
      "iam:CreateServiceLinkedRole",
    ]

    resources = [
      "arn:aws:iam::*:role/aws-service-role/redshift-data.amazonaws.com/AWSServiceRoleForRedshift",
    ]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"

      values = [
        "redshift-data.amazonaws.com",
      ]
    }
  }
}

data "aws_iam_policy_document" "redshift_policy" {

  statement {
    actions = [
      "redshift:*",
      "redshift-serverless:*",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
      "ec2:DescribeInternetGateways",
      "sns:CreateTopic",
      "sns:Get*",
      "sns:List*",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:EnableAlarmActions",
      "cloudwatch:DisableAlarmActions",
      "tag:GetResources",
      "tag:UntagResources",
      "tag:GetTagValues",
      "tag:GetTagKeys",
      "tag:TagResources"

    ]

    resources = [
      "*"
    ]
  }
}

data "aws_iam_policy_document" "service_linked_role_policy" {

  statement {

    actions = [
      "iam:CreateServiceLinkedRole",
    ]

    resources = [
      "arn:aws:iam::*:role/aws-service-role/redshift.amazonaws.com/AWSServiceRoleForRedshift",
    ]
    condition {
      test     = "StringLike"
      variable = "iam:AWSServiceName"

      values = [
        "redshift.amazonaws.com",
      ]
    }
  }
}

data "aws_iam_policy_document" "data_api_permissions_policy" {

  statement {
    sid = "DataAPIPermissions"
    actions = [
      "redshift-data:ExecuteStatement",
      "redshift-data:CancelStatement",
      "redshift-data:ListStatements",
      "redshift-data:GetStatementResult",
      "redshift-data:DescribeStatement",
      "redshift-data:ListDatabases",
      "redshift-data:ListSchemas",
      "redshift-data:ListTables",
      "redshift-data:DescribeTable",
      "redshift-data:BatchExecuteStatement",

    ]

    resources = [
      "*"
    ]
  }
}

data "aws_iam_policy_document" "secrets_manager_list_policy" {

  statement {
    sid = "SecretsManagerListPermissions"
    actions = [
      "secretsmanager:ListSecrets",

    ]

    resources = [
      "*"
    ]
  }
}

data "aws_iam_policy_document" "secrets_manager_create_policy" {

  statement {
    sid = "SecretsManagerCreateGetPermissions"

    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:TagResource"
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringLike"
      variable = "secretsmanager:ResourceTag/RedshiftDataFullAccess"

      values = [
        "*",
      ]
    }
  }

}


resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.schedule_query_role.name
  policy_arn = aws_iam_policy.schedule_query_policy.arn
}


resource "aws_redshift_cluster" "cluster" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "exampleuser"
  master_password    = "Omolade11*"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  iam_roles          = [aws_iam_role.schedule_query_role.arn]
  depends_on         = [aws_iam_role.schedule_query_role]
  skip_final_snapshot = true

}


resource "aws_cloudwatch_event_rule" "trial" {
  name                = "to-schedule-query"
  description         = "schedule query in redshift"
  schedule_expression = "cron(0/1 * ? * MON-FRI *)"
}

resource "aws_cloudwatch_event_target" "to_schedule_query" {
  target_id = "to-schedule-query"
  arn       = aws_redshift_cluster.cluster.arn
  rule      = aws_cloudwatch_event_rule.trial.name
  role_arn  = aws_iam_role.schedule_query_role.arn
  depends_on = [aws_iam_role.schedule_query_role, aws_cloudwatch_event_rule.trial, aws_redshift_cluster.cluster]
  redshift_target{
    database = "mydb"
    db_user = "exampleuser"
    sql = "select * from event;"
    statement_name = "refresh-schedule"
    with_event = true

  }

}
