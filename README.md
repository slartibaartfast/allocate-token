# A token allocator service

This is a service that is for creating and securing access tokens for apps to use with Astra and the Astra APIs.  It is packaged in a Docker container, and run in a kubernetes cluster.  It intends to circumvent building Astra connection credentials into apk or similar files which are distributed to end users by issueing and storing connection tokens and uuids to individual app users.

Prerequisites/Requirements:
  1) An [Astra](https://astra.datastax.com/register) database
  2) A repository for [Docker](https://www.docker.com/) images, such as [Docker Hub](https://hub.docker.com/)
  3) Access to a [Kubernetes](https://kubernetes.io/) cluster, or a local installation of [Kind](https://kubernetes.io/docs/setup/learning-environment/kind/), or [Minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
  4) An [OpenSSL](https://www.openssl.org/) toolkit locally or in Docker
  5) (Optional) A modern version of [Python](https://www.python.org/), for running GraphQL test queries


### Install tables and sample data in an Astra keyspace

Create two new keyspaces, one for secret data named app_manager and one that will store app generated data named tribe.  Refer to this [Astra documentation](https://docs.astra.datastax.com/docs/managing-keyspaces) as needed.


Create a roll with limited permissions for the app to use by opening a CQL prompt in the top level keyspace and running:
```
CREATE ROLE app_user WITH PASSWORD = 'AUniquePassword' AND LOGIN = true;
```
Grant limited permissions to the role by running:
```
GRANT DESCRIBE ON KEYSPACE tribe to app_user;
GRANT UPDATE ON KEYSPACE tribe TO app_user;
GRANT SELECT ON KEYSPACE tribe TO app_user;
```

Two .cql scripts are included to create a set of tables used by the not-yet-complete geolocation sharing mobile app [Tribe](http://tribe.posfoundations.com/).
In a CQL Console, run the CQL in astra_backend.cql to create the tables used by the service and by the app.  Once the tables have been created, run the CQL in sample_data.cql to populate the tables with a small amount of data.
Now we have fake user and app data to work with.


### For running locally in Kind...

Follow the instructions at
https://kind.sigs.k8s.io/docs/user/ingress/
1) run kind-config.yaml
2) set up an ingress
```
kubectl apply -f https://projectcontour.io/quickstart/contour.yaml
```

and add the kind patch
```
kubectl patch daemonsets -n projectcontour envoy -p '{"spec":{"template":{"spec":{"nodeSelector":{"ingress-ready":"true"},"tolerations":[{"key":"node-role.kubernetes.io/master","operator":"Equal","effect":"NoSchedule"}]}}}}'
```


### Add secrets to kubernetes...

Let's create a certificate, key and secret for the web server.  We will also create secrets used to connect to an Astra database.  And then we will create several more secrets to hold sensitive information in environmental variables that we will inject into our pods.

Pick a more permanent location for the files if you like - /tmp may be purged depending on your operating system.

Create a public private key pair that will be bound to the pod and used by the web server :
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/tls.key -out  /tmp/tls.crt -subj "/CN=my-allocator-w3/O=my-allocator-w3"
```

The output should be something like:
```
Generating a 2048 bit RSA private key
....................................................+++
......................+++
writing new private key to '/tmp/tls.key'
-----
```


### Download the secure connect bundle for your Astra database

On the Summary page of the [Astra](astra.datastax.com) database instance there is a link to download this bundle.  It has several files we will make secrets with.
Download the file and unpackage it in a convenient directory.


### Create Kubernetes Secrets

The allocatorw3secret will let data be served by the webserver over https.

Create the secret by running this command:
```
kubectl create secret tls allocatorw3secret --cert=/tmp/tls.crt --key=/tmp/tls.key
```
The output should be something like:
```
secret "allocatorw3secret" created
```

Create kubernetes secrets used to connect to Astra using files in the secure connection bundle for your Astra database.  First, download the secure connect bundle, then change directories to that cert location before running...
```
kubectl create secret tls astratls --cert=/tmp/cert --key=/tmp/key
kubectl create secret generic astraca --from-file=astraca=/tmp/ca.crt
```

Now we can create some secrets to hold information used by the service which will be injected into the pod upon its creation.  

First, we can add the name of our app management keyspace to an environmental variable named 'astraappmanagerkeyspace'.
```
kubectl create secret generic astraappmanagerkeyspace --from-literal=astraappmanagerkeyspace='app_manager'
```

Next, we can add the name of our app keyspace to an environmental variable named 'astraappkeyspace'.
```
kubectl create secret generic astraappkeyspace --from-literal=astraappkeyspace='tribe'
```

The astraadmincreds secret holds the username and password used to log in to your Astra instance.  Replace 'AdminUser' and 'AdminPassword' with your login credentials.
```
kubectl create secret generic astraadmincreds --from-literal=adminusername='AdminUser' --from-literal=adminpassword='AdminPassword'

```

The astratribeappcreds secret holds the username and password used to log in to the tribe keyspace.
```
kubectl create secret generic astratribeappcreds --from-literal=tribeappusername='TAUser' --from-literal=tribeapppassword='TAPassword'
```

The astraapiendpoint variable holds the endpoint we connect to for authentication as described in [the documentation](https://docs.astra.datastax.com/docs/generating-authorization-token)
Please replace CLUSTER_ID and CLUSTER_REGION with your values, which look similar to '7127f729-b4c5-4864-a15b-dba15c82a88e' and 'us-east1'.
```
kubectl create secret generic astraapiendpoint --from-literal=astraapiendpoint='https://CLUSTER_ID-CLUSTER_REGION.apps.astra.datastax.com/api/rest/v1/auth'
```

The astracql host is similar, but points to a slightly different domain name.  Please replace CLUSTER_ID and CLUSTER_REGION with your values, which look similar to '7127f729-b4c5-4864-a15b-dba15c82a88e' and 'us-east1'.
kubectl create secret generic astracqlhost --from-literal=astracqlhost='CLUSTER_ID-CLUSTER_REGION.db.astra.datastax.com'


Many secrets later, see that the secrets exist by running:
```
kubectl get secrets
```

The output should contain the secrets:
```
NAME                      TYPE                                  DATA   AGE
allocatorw3secret         kubernetes.io/tls                     2      11m
astraadmincreds           Opaque                                2      11m
astraapiendpoint          Opaque                                1      11m
astraappkeyspace          Opaque                                1      11m
astraappmanagerkeyspace   Opaque                                1      11m
astraca                   Opaque                                1      11m
astracqlhost              Opaque                                1      11m
astratls                  kubernetes.io/tls                     2      11m
astratribeappcreds        Opaque                                2      11m
```

These secrets are referenced in service.yaml and in main.go.


### Building the service
Now that the environment is set up, we can compile our code.  We will use a Dockerfile that defines a two stage build which fetches the code we need from this repo, builds the executable, and copies it to a smaller alpine image.
The code in main.go uses the gocql package to create a connection to the database, the trumail verifier package to validate email addresses, and runs a web server with endpoints for working with user data.
In the below command, replace trota with your repository username, and tag it whatever you like.  In the Deployment section (spec.template.spec.containers[0].image) of the service.yaml file, enter the name of the image that is built when this is run...
```
docker build -t trota/token-allocator:0.1.0 .
```

After it's finished building, push it to your repository...
```
docker push trota/token-allocator:0.1.0
```


### Create a Pod with the service.
Change directory to the location of your local copy of this repository and run...
```
kubectl apply -f service.yaml
```

When running in kind, Forward the port 8000
```
kubectl port-forward service/token-allocator-service 8000:8000

```


### Get the Pod
Get a list of pods
```
kubectl get pods
```
should return something like
```
NAME                               READY   STATUS    RESTARTS   AGE
token-allocator-58c4cb5d68-rf78v   1/1     Running   0          1m
```


### Connect to the pod
Log into the pod and look around, perhaps at the log in /home/service/logs.  In the below command, replace *token-allocator-58c4cb5d68-rf78v* with the actual pod name.
```
kubectl exec --stdin --tty token-allocator-58c4cb5d68-rf78v /bin/ash
```
Change directory to the service's logs directory and look at the log
```
cd home/service/logs
ls
cat allocator-log.txt
```
Looking empty?  There will be more data after testing the endpoints.


### Test the endpoints
Send a curl request to the endpoint to fetch a token and uuid:
```
curl -k -u dogdogalina@mrdogdogalina.com:ff9k3l2 https://localhost:8000/authToken
```

If you have Python3 installed, or a Docker container with a Python3 environment, run test.py to test the Astra database GraphQL endpoint and the endpoints of our service.
Prior to running the script, edit the endpoint variables to use your cluster ID and region in the urls.
```
python3 test.py
```

You should see something that begins and ends something like:
```
Testing token and uuid retrieval...
token:  c416e172-a1c2-4316-9614-a7fa64170663
requestID:  b52cca03-b2af-4196-b27d-2a9708c504c5
...
Testing creating a user with an invalid email address
status code:  200

Tests completed

```


### Usage
In an app, call the service endpoint to retrieve an Astra login token and transaction uuid.  Pass the email and password as entered by the user in the app's login screen to retrieve a fresh token and requestID.
```
def get_astra_creds(email, password, appID):
    headers = {'x-app-id': appID}
    r = requests.get('https://localhost:8000/authToken',
        auth=HTTPBasicAuth(email, password),
        headers=headers,
        verify=False)

    token = r.authToken
    requestID = r.requestID

    return token, requestID
```

Later when connecting to Astra to get some data, use the token and requestID as credentials...

```
def get_user_location(token, requestID):
    qHeaders = {'accept': '*/*'}
    qHeaders['content-type'] = 'application/json'
    qHeaders['x-cassandra-request-id'] = requestID
    qHeaders['x-cassandra-token'] = token

    url = 'https://11111111-22w3-fds1-5555-949494949494-us-east1.apps.astra.datastax.com/api/graphql'

    q = """
    query {
      tribeMembers(value: {ownerId) {
        values {
                ownerId
                memberIds
        }
      }
    }
    """

    resp = requests.post(url=url,
            headers=qHeaders,
            json={'query': q})

    return resp

```


### Set up an A record
So that a subdomain can point to the ip address of the ingress


### Credits
[DataStax Academy](https://github.com/DataStax-Academy/cassandra-workshop-series)

[astra_gocql_connect](https://github.com/flightc/astra_gocql_connect)

[gocql](https://github.com/gocql/gocql)

[Trumail](https://github.com/trumail/trumail)




### License
[Apache](https://choosealicense.com/licenses/apache)
