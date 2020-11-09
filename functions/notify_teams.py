from __future__ import print_function
from urllib.error import HTTPError
import os
import boto3
import json
import base64
import urllib.request
import urllib.parse
import logging


# Decrypt encrypted URL with KMS
def decrypt(encrypted_url):
    region = os.environ['AWS_REGION']
    try:
        kms = boto3.client('kms', region_name=region)
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))[
            'Plaintext']
        return plaintext.decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")


def cloudwatch_notification(message, region):
    return {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.0",
            "body": [
                    {
                        "type": "Container",
                        "id": "847b8b15-67bc-6bd9-9daf-72460102654e",
                        "padding": "None",
                        "items": [
                            {
                                "type": "TextBlock",
                                "id": "85bb3cd7-e29d-49b2-3ea8-6cdef754dcdb",
                                "text": message['AlarmName'],
                                "wrap": True,
                                "size": "Large",
                                "weight": "Bolder"
                            },
                            {
                                "type": "TextBlock",
                                "id": "0cd0e877-6747-c4b7-8f53-ae05d3af4dea",
                                "text": message['AlarmDescription'],
                                "wrap": True,
                                "spacing": "None",
                                "isSubtle": True
                            },
                            {
                                "type": "FactSet",
                                "id": "646f86f5-56eb-69c9-3f10-08fffec73824",
                                "facts": [
                                    {
                                        "title": "Old State",
                                        "value": message['OldStateValue']
                                    },
                                    {
                                        "title": "New State",
                                        "value": message['NewStateValue']
                                    }
                                ],
                                "spacing": "Small"
                            }
                        ]
                    },
                {
                        "type": "Container",
                        "id": "abd1557d-6ae0-75f8-e69f-99a51eac4e93",
                        "padding": "None",
                        "separator": True,
                        "items": [
                            {
                                "type": "TextBlock",
                                "id": "15a0be5e-73ad-ae7e-72cd-410eedabdcc6",
                                "text": message['NewStateReason'],
                                "wrap": True
                            },
                            {
                                "type": "ActionSet",
                                "actions": [
                                    {
                                        "type": "Action.OpenUrl",
                                        "id": "c22b8bfd-df6e-ae8e-d8db-e417877a2d34",
                                        "title": "Open in AWS",
                                        "url": "https://console.aws.amazon.com/cloudwatch/home?region=" + region + "#alarm:alarmFilter=ANY;name=" + urllib.parse.quote(message['AlarmName']),
                                        "style": "positive",
                                        "isPrimary": True
                                    }
                                ]
                            }
                        ]
                }
            ],
            "padding": "Default"
        }
    }


def default_notification(subject, message):
    return {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.0",
            "body": [
                {
                    "type": "Container",
                    "id": "f610b454-128b-245e-e5e0-f618356aad56",
                    "padding": "Default",
                    "items": [
                        {
                            "type": "TextBlock",
                            "id": "5dc7eb53-531e-e589-ddb1-b4c3c0409a69",
                            "text": subject if subject else "Message",
                            "wrap": True,
                            "size": "Large",
                            "weight": "Bolder"
                        },
                        {
                            "type": "TextBlock",
                            "id": "e0c353ed-9dc8-8b1f-331e-e69c25f4525f",
                            "text": json.dumps(message) if type(message) is dict else message,
                            "wrap": True
                        }
                    ]
                }
            ],
            "padding": "None"
        }
    }


# Send a message to a teams channel
def notify_teams(subject, message, region):
    teams_url = os.environ['TEAMS_WEBHOOK_URL']
    if not teams_url.startswith("http"):
        teams_url = decrypt(teams_url)

    payload = {
        "type": "message",
        "attachments": []
    }

    if type(message) is str:
        try:
            message = json.loads(message)
        except json.JSONDecodeError as err:
            logging.exception(f'JSON decode error: {err}')

    if "AlarmName" in message:
        notification = cloudwatch_notification(message, region)
        payload['attachments'].append(notification)
    else:
        payload['attachments'].append(default_notification(subject, message))

    data = urllib.parse.urlencode(payload).encode("utf-8")
    print(data)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(teams_url)

    try:
        result = urllib.request.urlopen(req, data)
        return json.dumps({"code": result.getcode(), "info": result.info().as_string()})

    except HTTPError as e:
        logging.error("{}: result".format(e))
        return json.dumps({"code": e.getcode(), "info": e.info().as_string()})


def lambda_handler(event, context):
    if 'LOG_EVENTS' in os.environ and os.environ['LOG_EVENTS'] == 'True':
        logging.warning(
            'Event logging enabled: `{}`'.format(json.dumps(event)))

    subject = event['Records'][0]['Sns']['Subject']
    message = event['Records'][0]['Sns']['Message']
    region = event['Records'][0]['Sns']['TopicArn'].split(":")[3]
    response = notify_teams(subject, message, region)

    if json.loads(response)["code"] != 200:
        logging.error("Error: received status `{}` using event `{}` and context `{}`".format(
            json.loads(response)["info"], event, context))

    return response
