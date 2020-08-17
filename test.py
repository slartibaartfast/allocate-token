# coding=utf-8

import json
import urllib3
import requests
from requests.auth import HTTPBasicAuth
import uuid

# disable ssl warnings until we have proper certs
urllib3.disable_warnings()

qUrl = "https://6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.apps.astra.datastax.com/api/graphql"

#curl -k -u dogdogalina@mrdogdogalina.com:ff9k3l2 https://localhost:8000/
#r = requests.get('https://localhost:8000/', verify=False)
#print(r.content)

# retrieve a token and uuid from our service
def get_creds(email, password):
    #print("Getting auth token and requestID values...")
    r = requests.get('https://localhost:8000/authToken',
        auth=HTTPBasicAuth(email, password),
        verify=False)

    jsonr = r.json()
    token = jsonr["authToken"]
    requestID = jsonr["requestID"]

    print("token: ", token)
    print("requestID: ", requestID)
    print(" ")
    return token, requestID


# Use our token and uuid to query Astra
def get_user(token, requestID, userId):
    qHeaders = {'accept': '*/*'}
    qHeaders['content-type'] = 'application/json'
    qHeaders['x-cassandra-request-id'] = requestID
    qHeaders['x-cassandra-token'] = token

    url = qUrl

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


# Check to see if our service upserted the token and uuid into the user credentials table
def get_user_credentials(token, requestID):
    qHeaders = {'accept': '*/*'}
    qHeaders['content-type'] = 'application/json'
    qHeaders['x-cassandra-request-id'] = requestID
    qHeaders['x-cassandra-token'] = token

    url = qUrl

    q = """
    query {
      tribeUserCredentials(value: { email: "dogdogalina@mrdogdogalina.com" }) {
        values {
          email
          appToken
          appRequestId
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


# Attempt to retrieve credentials for a user that does not exist in our db
def wrong_username():
    r = requests.get('https://localhost:8000/authToken',
        auth=HTTPBasicAuth('idontexist@frankrizo.com', 'ff9k3l2'),
        verify=False)

    print("status code: ", r.status_code)

    return r.status_code


# Create a new user
def create_new_user(email, password):
    r = requests.get('https://localhost:8000/regUser',
        auth=HTTPBasicAuth(email, password),
        verify=False)

    print("status code: ", r.status_code)

    return r.status_code


# get a token and requestID using our go service
print("Testing token and uuid retrieval...")
token, requestID = get_creds('dogdogalina@mrdogdogalina.com', 'ff9k3l2'),)
assert token == str(uuid.UUID(token)), "Fail"
assert requestID == str(uuid.UUID(requestID)), "Fail"
print(" ")

# query the Astra db using the token and uuid
print("Testing that the token and uuid can be used to query Astra...")
user = get_user(token, requestID)
user = user.json()
assert user['data']['tribeUsers']['values'][0]['email'] == "dogdogalina@mrdogdogalina.com", "Fail"
print(" ")

# query the Astra db to see if our service updated the tribe_user_credentials
# table with the new token
# assert that tribe_user_credentials.app_token equals the variable named token
print("Testing that we upserted the user credentials table with the token and uuid...")
user_creds = get_user_credentials(token, requestID)
user_creds = user_creds.json()
assert user_creds['data']['tribeUserCredentials']['values'][0]['appToken'] == str(token), "Fail"
assert user_creds['data']['tribeUserCredentials']['values'][0]['appRequestId'] == str(requestID), "Fail"
print(" ")

# test if we identify nonexistant user
print("Testing that submitting an invalid username returns a status of 404...")
wrong_username = wrong_username()
assert wrong_username == 404, "Fail"
print(" ")

# test creating a new user with a valid email address
#curl -k -u realemail@realdomain.com:Password https://localhost:8000/regUser
print("Testing creating a user with a valid email address")
new_user = create_new_user('mrtomrota@gmail.com', 'Password')

#test creating a new user with an invalid email address
#curl -k -u idontexist@frankrizo.com:Password https://localhost:8000/regUser
new_user = create_new_user('idontexists@frankrizo.com', 'Password')


print("Tests completed")
