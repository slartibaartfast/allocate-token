# coding=utf-8

import json
import urllib3
import requests
from requests.auth import HTTPBasicAuth

# disable ssl warnings until we have proper certs
urllib3.disable_warnings()

#curl -k -u v1GameClientKey:EAEC945C371B2EC361DE399C2F11E https://localhost:8000/
#r = requests.get('https://localhost:8000/', verify=False)
#print(r.content)

def get_user():
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

get_user()

# TODO:
# assert that email equals "dogdogalina@mrdogdogalina.com"
