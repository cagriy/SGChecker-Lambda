from __future__ import print_function

import json
import boto3
import os
import psutil

ENVIRONMENT = os.environ.get('ENVIRONMENT')
SNS_ARN = os.environ.get('SNS_ARN')

RISKY_PORTS = [20, 21, 22, 1433, 1434, 3306, 3389, 4333, 5432, 5500]
template = """
Security Group Alert !
Alert Level : {0}
Account: {1}
Region: {2}
Event Time: {3}
Detail: {4}

"""

print('Loading function')


def aws_send_sns_message(message, topic_arn):
    # type: (string, string, string, string) -> string
    # TODO:  Unit Testing
    print(topic_arn)
    topic_keys = topic_arn.split(':', 5)
    region = topic_keys[3]
    aws_client = boto3.client(
        "sns",
        region_name=region
    )
    response = aws_client.publish(
        TopicArn=topic_arn,
        Message=message
    )
    return response


def lambda_handler(event, context):
    print(str(event))
    account = event['account']
    region = event['region']
    event_time = event['detail']['eventTime']
    message = ""
    for item in event['detail']['requestParameters']['ipPermissions']['items']:
        from_port = item['fromPort']
        to_port = item['toPort']
        print(str(to_port))
        print(item['ipProtocol'])
        print(item['ipRanges']['items'])
        affected_ports = []
        if item['ipProtocol'] == '-1' and json.dumps(item['ipRanges']['items']).find('0.0.0.0/0'):
            message += template.format('Critical', account, region, event_time, 'All ports open to the world !')
        if item['ipProtocol'] == 'tcp' and json.dumps(item['ipRanges']['items']).find('0.0.0.0/0'):
            for port in RISKY_PORTS:
                if from_port <= port <= to_port:
                    affected_ports.append(port)
            if len(affected_ports) > 0:
                message += template.format('Important', account, region, event_time,
                                           'TCP port(s) ' + ",".join(
                                               str(x) for x in affected_ports) + ' open to the world !')
            else:
                message += template.format('Warning', account, region, event_time,
                                           'TCP port' + (
                                           ' ' + str(to_port) if to_port == from_port else 's from ' + str(
                                           from_port) + ' to ' + str(to_port)) + ' open to the world !')

    if message != "":
        message += "Raw Event:\n" + json.dumps(event, indent=4, sort_keys=True)
        print('Notification sent.')
        if ENVIRONMENT == "IDE":
            print(message)
        else:
            aws_send_sns_message(message, SNS_ARN)

    if ENVIRONMENT == "LAMBDA":
        print('Time remaining (ms) : ' + str(context.get_remaining_time_in_millis()))
    return message


if ENVIRONMENT == "IDE":
    with open('dummy_event.json') as event_file:
        event = json.load(event_file)
    lambda_handler(event, 'no context')
    print(psutil.Process(os.getpid()).memory_info_ex().peak_wset)
