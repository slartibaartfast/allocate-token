# coding=utf-8

import json
import urllib3
import requests
from requests.auth import HTTPBasicAuth
import unittest

# disable ssl warnings until we have proper certs
urllib3.disable_warnings()

#curl -k -u v1GameClientKey:EAEC945C371B2EC361DE399C2F11E https://localhost:8000/
#r = requests.get('https://localhost:8000/', verify=False)
#print(r.content)

def get_creds():
    print("Getting auth token and requestID values...")
    r = requests.get('https://localhost:8000/authToken',
        auth=HTTPBasicAuth('v1GameClientKey', 'EAEC945C371B2EC361DE399C2F11E'),
        verify=False)

    jsonr = r.json()
    token = jsonr["authToken"]
    requestID = jsonr["requestID"]

    print("token: ", token)
    print("requestID: ", requestID)
    print(" ")
    return token, requestID

def get_user(token, requestID):

    qHeaders = {'accept': '*/*'}
    qHeaders['content-type'] = 'application/json'
    qHeaders['x-cassandra-request-id'] = requestID
    qHeaders['x-cassandra-token'] = token

    url = "https://6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.apps.astra.datastax.com/api/graphql"

    q = """
    query {
      tribeUsers(value: { userId: "00000000-0000-0000-0000-000000000000" }) {
        values {
          userName
          dateCreated
          email
          lastLogin
        }
      }
    }
    """

    resp = requests.post(url=url,
            headers=qHeaders,
            json={'query': q})

    #print("body: ", resp.request.body)
    #print("headers: ", resp.request.headers)
    print(" ")
    print("response: ", resp.text)

    return resp


def get_user_credentials(token, requestID):
    qHeaders = {'accept': '*/*'}
    qHeaders['content-type'] = 'application/json'
    qHeaders['x-cassandra-request-id'] = requestID
    qHeaders['x-cassandra-token'] = token

    url = "https://6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.apps.astra.datastax.com/api/graphql"

    q = """
    query {
      tribeUserCredentials(value: { email: "dogdogalina@mrdogdogalina.com" }) {
        values {
          email
          appToken
          password
          userId
        }
      }
    }
    """

    resp = requests.post(url=url,
            headers=qHeaders,
            json={'query': q})

    #print("body: ", resp.request.body)
    #print("headers: ", resp.request.headers)
    print(" ")
    print("response: ", resp.text)

    return resp

# get a token and requestID using our go service
token, requestID = get_creds()
assert len(token) > 0
assert len(requestID) > 0

# query the Astra db using the token and uuid
user = get_user(token, requestID)
user = user.json()
assert user['data']['tribeUsers']['values'][0]['email'] == "dogdogalina@mrdogdogalina.com"

# query the Astra db to see if our service updated the tribe_user_credentials
# table with the new token
# assert that tribe_user_credentials.app_token equals the variable named token
user_creds = get_user_credentials(token, requestID)
user_creds = user_creds.json()
assert user_creds['data']['tribeUserCredentials']['values'][0]['appToken'] == str(token)
assert user_creds['data']['tribeUserCredentials']['values'][0]['appRequestId'] == str(requestID)
