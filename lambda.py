'''Function that will take in final scan results from the Inspector2 Scan event bridge message \
and evaluate the results to determine if the image can be deployed'''

import os
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def log_final_results(approval,image_digest, repository_arn, image_tags, reason, sev_list):
  '''Writes the final results of the image vulnerability assessment'''

  logger.info('***********************************')
  logger.info('Final container vulnerability assessment details')
  logger.info('------------------------')
  logger.info('Approval Status: %s', approval)
  logger.info('Approval Reason: %s', reason)
  logger.info('ImageDigest: %s', image_digest)
  logger.info('ImageARN: %s', repository_arn)
  logger.info('Image Tags: %s', image_tags)
  logger.info('Critical Vulnerabilities: %s', sev_list.get('CRITICAL',0))
  logger.info('High Vulnerabilities: %s', sev_list.get('HIGH',0))
  logger.info('Medium Vulnerabilities: %s', sev_list.get('MEDIUM',0))
  logger.info('***********************************')

## Main ##
def lambda_handler(event, context):
  '''Main lambda handler'''

  logger.info('Event Data')
  logger.info(event)

  scan_status = event["detail"]["scan-status"]
  logger.info('Event scan status: %s', scan_status)

  # We only want to move forward if the scan status is SUCCESSFUL
  if scan_status != 'INITIAL_SCAN_COMPLETE':
    logger.info('Scan status is not successful.  Not processing further.')
    #we can use this status to fail the pipeline if needed
    return 'Scan status is not successful.  Not processing further.'


  repository_arn = event["detail"]["repository-name"]
  logger.info('Repository ARN: %s', repository_arn)
  resource_type = repository_arn.split(":")[2]
  logger.info('Resource type: %s', resource_type)

  # Only move forward if the resource type in the message is ecr
  if resource_type != 'ecr':
    logger.info('Resource Type: %s', resource_type)
    logger.info('Resource type is not ECR.  Exiting.')
    return 'Resource type is not ECR.  Exiting.'

  image_digest = event["detail"]["image-digest"]
  image_tags = event["detail"]["image-tags"]
  logger.info('Image digest: %s', image_digest)
  logger.info('Image tags: %s', image_tags)


  # Compare finding severity counts against thresholds

  critical_max = int(os.environ['Critical_Finding_Threshold'])
  high_max = int(os.environ['High_Finding_Threshold'])
  medium_max = int(os.environ['Medium_Finding_Threshold'])
  threshold_breach = False

  if event["detail"]["finding-severity-counts"]["CRITICAL"] !=0 \
      and event["detail"]["finding-severity-counts"]["CRITICAL"] >= critical_max:

    threshold_breach = True
    logger.info("*******************************")
    logger.info("We have a CRITICAL vulnerability")
    logger.info("*******************************")

    deploy_approved='Rejected'
    reason=f'Critical vulnerability threshold of {critical_max} exceeded'

    logger.info('Deployment is NOT approved')
    logger.info('Writing final results')

    log_final_results(deploy_approved, image_digest, repository_arn, image_tags, \
              reason, event["detail"]["finding-severity-counts"])

    return reason

  if event["detail"]["finding-severity-counts"]["HIGH"] != 0 \
      and event["detail"]["finding-severity-counts"]["HIGH"] >= high_max:

    threshold_breach = True
    logger.info ("*******************************")
    logger.info ("We have a HIGH vulnerability")
    logger.info ("*******************************")

    deploy_approved='Rejected'
    reason=f'High vulnerability threshold of {high_max} exceeded'

    logger.info('Deployment is NOT approved')
    logger.info('Writing final results')

    log_final_results(deploy_approved, image_digest, repository_arn, image_tags, \
              reason, event["detail"]["finding-severity-counts"])

    return reason

  if event["detail"]["finding-severity-counts"]["MEDIUM"] != 0 \
      and event["detail"]["finding-severity-counts"]["MEDIUM"] >= medium_max:

    threshold_breach = True
    logger.info ("*******************************")
    logger.info ("We have a MEDUIM vulnerability")
    logger.info ("*******************************")

    deploy_approved='Rejected'
    reason=f'Medium vulnerability threshold of {medium_max} exceeded'

    logger.info('Deployment is NOT approved')
    logger.info('Writing final results')

    log_final_results(deploy_approved, image_digest, repository_arn, image_tags,\
              reason, event["detail"]["finding-severity-counts"])

    return reason

  if threshold_breach is False:
    #None of the other threshold statements triggered so we are assuming good to go

    deploy_approved = 'Approved'
    reason='All vulnerabilities below thresholds'

    logger.info('Deployment IS approved')
    logger.info('Writing final results')

    log_final_results(deploy_approved, image_digest, repository_arn, image_tags,\
              reason, event["detail"]["finding-severity-counts"])

  return {
        'statusCode': 200,
    }
