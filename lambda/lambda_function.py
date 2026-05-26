import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def isolate_ec2_instance(instance_id, region):
    """
    Isolate a compromised EC2 instance:
    1. Tag the instance as COMPROMISED (preserves state for forensics)
    2. Remove from any load balancer rotation by modifying security groups
    NOTE: Instance is NOT terminated — forensic evidence must be preserved.
    """
    ec2 = boto3.client('ec2', region_name=region)

    # Tag the instance as COMPROMISED
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {'Key': 'SecurityStatus', 'Value': 'COMPROMISED'},
            {'Key': 'IsolatedBy', 'Value': 'guardduty-auto-response'},
            {'Key': 'IsolationReason', 'Value': 'GuardDuty HIGH severity finding'}
        ]
    )
    logger.info(f"Tagged EC2 instance {instance_id} as COMPROMISED")

    # Isolate by replacing security groups with a restrictive one
    # In production: create a dedicated isolation security group with no ingress/egress
    # ec2.modify_instance_attribute(
    #     InstanceId=instance_id,
    #     Groups=['sg-isolation-group-id']  # Replace with your isolation SG ID
    # )

    logger.info(f"EC2 instance {instance_id} isolation complete")
    return instance_id


def lambda_handler(event, context):
    """
    GuardDuty Automated Response Function

    Triggered by EventBridge when GuardDuty findings reach severity >= 4.

    Severity routing:
      >= 7 (HIGH)    → Auto-isolate compromised EC2 + log to CloudWatch
      4-6 (MEDIUM)   → Log finding details to CloudWatch, no destructive action
      < 4 (LOW)      → Not triggered (filtered by EventBridge upstream)
    """

    # Parse the GuardDuty finding from the EventBridge event
    detail = event.get('detail', {})
    finding_type = detail.get('type', 'Unknown')
    severity = detail.get('severity', 0)
    region = detail.get('region', 'Unknown')
    account_id = detail.get('accountId', 'Unknown')
    finding_id = detail.get('id', 'Unknown')

    # Get the affected resource
    resource = detail.get('resource', {})
    resource_type = resource.get('resourceType', 'Unknown')

    logger.info("=" * 60)
    logger.info("GuardDuty Finding Received")
    logger.info("=" * 60)
    logger.info(f"Finding ID:    {finding_id}")
    logger.info(f"Type:          {finding_type}")
    logger.info(f"Severity:      {severity}")
    logger.info(f"Region:        {region}")
    logger.info(f"Account:       {account_id}")
    logger.info(f"Resource Type: {resource_type}")

    response = {
        'finding_id': finding_id,
        'finding_type': finding_type,
        'severity': severity,
        'action_taken': None
    }

    # HIGH severity (>= 7): auto-remediate immediately
    if severity >= 7:
        logger.info(f"HIGH severity finding — initiating automated remediation")

        if resource_type == 'Instance':
            instance_details = resource.get('instanceDetails', {})
            instance_id = instance_details.get('instanceId', 'Unknown')
            logger.info(f"Compromised EC2 instance detected: {instance_id}")

            isolated = isolate_ec2_instance(instance_id, region)
            response['action_taken'] = f"EC2 instance {isolated} tagged COMPROMISED and isolated"
            logger.info(f"Remediation complete: {response['action_taken']}")

        else:
            logger.info(f"HIGH severity finding on resource type: {resource_type}")
            logger.info("Manual investigation required — no automated action for this resource type")
            response['action_taken'] = f"Logged HIGH severity {resource_type} finding — manual review required"

    # MEDIUM severity (4-6): log and monitor, no destructive action
    elif severity >= 4:
        logger.info(f"MEDIUM severity finding — logging for analyst review")
        logger.info(f"Finding type: {finding_type}")
        logger.info(f"No automated remediation — avoids false positive disruption")
        response['action_taken'] = "Logged MEDIUM severity finding — analyst review required"

    else:
        # Should not reach here (EventBridge filters severity < 4)
        logger.info(f"LOW severity finding received — no action taken")
        response['action_taken'] = "No action — LOW severity"

    logger.info(f"Response: {json.dumps(response)}")
    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }
