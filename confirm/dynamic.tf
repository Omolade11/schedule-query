provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "schedule_query_role" {
  name               = "schedule_query"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonRedshiftDataFullAccess", "arn:aws:iam::aws:policy/AmazonEventBridgeFullAccess", "arn:aws:iam::aws:policy/AmazonRedshiftFullAccess"]
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
      identifiers = ["arn:aws:iam::377582181475:user/cloudformation"]
    }
  }
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



/*
locals {
  cron = ["cron(0/1 * ? * MON-FRI *)", "cron(0/10 * ? * MON-FRI *)", "cron(0/30 * ? * MON-FRI *)"]
  sql = ["CREATE TABLE Persons (FirstName varchar(255));", "CREATE DATABASE testdata;", "select * from event;"] 
 }   
 */



variable "cron" {
  type = list
  default = ["cron(0/1 * ? * MON-FRI *)", "cron(0/10 * ? * MON-FRI *)", "cron(0/30 * ? * MON-FRI *)"]
}
variable "sql" {
  type = list
  default =  ["CREATE TABLE Persons (FirstName varchar(255));", "CREATE DATABASE testdata;", "select * from event;"] 
}

 variable "event_rule_name" {
  type = string
  default = "to_schedule_query"
}

variable "counter"{
  type = number
  default = 3
}

    
resource "aws_cloudwatch_event_rule" "trial" {
  name                = "${var.event_rule_name}-${count.index}"
  description         = "schedule query in redshift"
  schedule_expression = var.cron[count.index]
  count = var.counter
}


resource "aws_cloudwatch_event_target" "to_schedule_query" {
  arn        = aws_redshift_cluster.cluster.arn
  rule       = "${var.event_rule_name}-${count.index}"
  role_arn   = aws_iam_role.schedule_query_role.arn
  redshift_target {
    database       = "mydb"
    db_user        = "exampleuser"
    sql            = var.sql[count.index]
    statement_name = "refresh-schedule"
    with_event     = true

  }
  count =  var.counter

}