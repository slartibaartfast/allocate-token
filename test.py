# coding=utf-8

import json
import urllib3
import requests
from requests.auth import HTTPBasicAuth
import uuid

# disable ssl warnings until we have proper certs
urllib3.disable_warnings()

# A Datastax GraphQl api endpoint
qUrl = "https://${ASTRA_CLUSTER_ID}-${ASTRA_CLUSTER_REGION}.apps.astra.datastax.com/api/graphql"

# The rest api endpoint for fetching a user in the tribe keyspace
restUserUrl = "https://${ASTRA_CLUSTER_ID}-${ASTRA_CLUSTER_REGION}.apps.astra.datastax.com/api/rest/v1/keyspaces/tribe/tables/tribe_users/rows/00000000-0000-0000-0000-000000000000"

# The rest api enpoint for getting user credentials from the app_manager keyspace
restUserCredsUrl = "https://${ASTRA_CLUSTER_ID}-${ASTRA_CLUSTER_REGION}.apps.astra.datastax.com/api/rest/v1/keyspaces/app_manager/tables/tribe_user_credentials/rows/dogdogalina@mrdogdogalina.com"

# The app_id that was created by the insert statemnt in sample_data.cql
appID = 'db9b4884-32db-4bbe-9869-63ce537bd250'

# A user id created while loading testing data
userID = '00000000-0000-0000-0000-000000000000'

#curl -k -u dogdogalina@mrdogdogalina.com:ff9k3l2 https://localhost:8000/
#r = requests.get('https://localhost:8000/', verify=False)
#print(r.content)

# retrieve a token and uuid from our service's authToken endpoint
def get_creds(email, password, appID):
    #print("Getting auth token and requestID values...")
    headers = {'x-app-id': appID}
    r = requests.get('https://localhost:8000/authToken',
        auth=HTTPBasicAuth(email, password),
        headers=headers,
        verify=False)

    jsonr = r.json()
    token = jsonr["authToken"]
    requestID = jsonr["requestID"]

    print("token: ", token)
    print("requestID: ", requestID)
    print(" ")
    return token, requestID


def get_user_rest(token, requestID):
    headers = {'content-type' : 'application/json'}
    headers['x-cassandra-request-id'] = requestID
    headers['x-cassandra-token'] = token
    url = restUserUrl

    resp = requests.get(url=url,
            headers=headers)

    #print("response: ", resp.text)

    return resp


def get_user_credentials_rest(token, requestID):
    headers = {'content-type' : 'application/json'}
    headers['x-cassandra-request-id'] = requestID
    #headers['x-cassandra-request-id'] = "320672b0-6a99-42dc-b642-7be1056bb334"
    headers['x-cassandra-token'] = token
    url = restUserCredsUrl
    resp = requests.get(url=url,
            headers=headers)

    print("status code: ", resp.status_code)

    return resp


# Use our token and uuid to query Astra
# TODO: pass userID as a variable
#tribeUsers(value: { userId: "00000000-0000-0000-0000-000000000000" }) {
# TODO: why does this pass userID - because it should be a variable in the query
def get_user(token, requestID, userID):
    qHeaders = {'accept': '*/*'}
    qHeaders['content-type'] = 'application/json'
    qHeaders['x-cassandra-request-id'] = requestID
    #qHeaders['x-cassandra-request-id'] = "320672b0-6a99-42dc-b642-7be1056bb334"
    qHeaders['x-cassandra-token'] = token

    url = qUrl
#tribeUsers(value: {userId: $userId}) {
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
    #variables = {'email': email}
    #variables = {'userId': userID}
    #print("variables: ", variables)
    resp = requests.post(url=url,
            headers=qHeaders,
            #json={'query': q, 'variables': variables})
            json={'query': q})


    #print("body: ", resp.request.body)
    #print("headers: ", resp.request.headers)
    #print(" ")
    print("response: ", resp.text)

    return resp


# Check to see if the app user has access to the user credentials table
# TODO: pass email as a variable
def get_user_credentials(token, requestID):
    qHeaders = {'accept': '*/*'}
    qHeaders['content-type'] = 'application/json'
    qHeaders['x-cassandra-request-id'] = requestID
    qHeaders['x-cassandra-token'] = token

    url = qUrl

    q = """
    query {
      tribeUserCredentials(value: {
                                  email: "dogdogalina@mrdogdogalina.com",
                                  appId: "9edd2f70-b50b-4c01-b216-701471889ccd",
                                  password:"ff9k3l2"
                                  }) {
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

    return resp


# Attempt to retrieve credentials for a user that does not exist in our db
def wrong_username(username, password, appID):
    headers = {'x-app-id': appID}
    r = requests.get('https://localhost:8000/authToken',
        headers=headers,
        auth=HTTPBasicAuth(username, password),
        verify=False)

    print("status code: ", r.status_code)

    return r.status_code


# Create a new user
def create_new_user(email, password, appID):
    headers = {'x-app-id': appID}
    r = requests.get('https://localhost:8000/regUser',
        headers=headers,
        auth=HTTPBasicAuth(email, password),
        verify=False)

    print("status code: ", r.status_code)

    return r.status_code


# get a token and requestID using our go service
print("Testing token and uuid retrieval...")
token, requestID = get_creds('dogdogalina@mrdogdogalina.com', 'ff9k3l2', appID)
assert token == str(uuid.UUID(token)), "Fail"
assert requestID == str(uuid.UUID(requestID)), "Fail"
print(" ")

# query the Astra db using the token and uuid
print("Testing that the token and uuid can be used to query Astra tribe \
keyspace via the rest endpoint...")
user = get_user_rest(token, requestID)
user = user.json()
#print("user: ", user)
assert user['rows'][0]['email'] == "dogdogalina@mrdogdogalina.com", "Fail"
print("Pass")
print(" ")

print("Testing that the app user cannot query the app_manager keyspace \
via the rest endpoint...")
user = get_user_credentials_rest(token, requestID)
#user = user.json()
assert user.status_code == 500, "Fail"
print("Pass")
print(" ")



#print("Testing that the token and uuid can be used to query Astra tribe \
#       keyspace via the GraphQL enpoint...")
#user = get_user(token, requestID, userID)
#user = user.json()
#assert user['data']['tribeUsers']['values'][0]['email'] == "dogdogalina@mrdogdogalina.com", "Fail"
#print(" ")

# query the Astra db to see if our service updated the tribe_user_credentials
# table with the new token
# assert that tribe_user_credentials.app_token equals the variable named token
#print("Testing that the app user cannot query the app_manager keyspace...")
#user_creds = get_user_credentials(token, requestID)
#user_creds = user_creds.json()
#print("user_creds: ", user_creds)
#assert user_creds['data']['tribeUserCredentials']['values'][0]['appToken'] == str(token), "Fail"
#assert user_creds['data']['tribeUserCredentials']['values'][0]['appRequestId'] == str(requestID), "Fail"
#print(" ")

# test if we identify nonexistant user
print("Testing that submitting an invalid username returns a status of 404...")
wrong_username = wrong_username('idontexist@frankrizo.com', 'ff9k3l2', appID)
assert wrong_username == 404, "Fail"
print("Pass")
print(" ")

# test creating a new user with a valid email address
#curl -k -u realemail@realdomain.com:Password https://localhost:8000/regUser
print("Testing creating a user with a valid email address")
new_user = create_new_user('trota@posfoundations.com', 'Password', appID)
assert new_user == 200, "Fail"
print("Pass")
print(" ")

#test creating a new user with an invalid email address
#curl -k -u idontexist@frankrizo.com:Password https://localhost:8000/regUser
print("Testing creating a user with an invalid email address")
non_user = create_new_user('idontexists@frankrizo.com', 'Password', appID)
assert non_user == 404, "Fail"
print("Pass")
print(" ")

print("Tests completed")
