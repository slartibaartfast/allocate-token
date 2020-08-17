# A token allocator service

This is a service that is for creating and securing access tokens for apps to use with Astra and the Astra APIs.  It is packaged in a Docker container, and run in a kubernetes cluster.  It intends to circumvent building Astra connection credentials into apk or similar files which are distributed to end users by issueing and storing connection tokens and uuids to individual app users.

Prerequisites:
  1) An [Astra](https://astra.datastax.com/register) database
  2) A repository for [Docker](https://www.docker.com/) images, such as [Docker Hub](https://hub.docker.com/)
  3) Access to a [Kubernetes](https://kubernetes.io/) cluster, or a local installation of [Kind](https://kubernetes.io/docs/setup/learning-environment/kind/), or [Minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
  4) An [OpenSSL](https://www.openssl.org/) toolkit locally or in Docker
  5) (Optional) A modern version of [Python](https://www.python.org/), for running GraphQl test queries


### Install tables and sample data in an Astra keyspace
Two .cql scripts are included to create a set of tables used by the not-yet-complete geolocation sharing mobile app [Tribe](http://tribe.posfoundations.com/).
In a CQL Console, run the CQL in astra_backend.cql to create a keyspace named killrvideo, the tables used by the app Tribe.  Once the tables have been created, run the CQL in sample_data.cql to populate the tables with a small amount of data.
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
Let's keep security in mind from the beginning by creating a certificate, key and secret for the web server.  We will also create secrets used to connect to an Astra database.  And then we will create several more secrets to hold sensitive information in environmental variables.

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

Now we can create some secrets to hold information used by the service which will be injected into the pod upon its creation.  First, we can add the name of our keyspace to an environmental variable named 'astrakeyspace'.
```
kubectl create secret generic astrakeyspace --from-literal=astrakeyspace='killrvideo'
```

The astracreds secret holds the username and password used to log in to your Astra keyspace.  Replace 'KVUser' and 'KVPassword' with your login credentials for this keyspace.
```
kubectl create secret generic astracreds --from-literal=adminusername='KVUser' --from-literal=adminpassword='KVPassword'
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
NAME                  TYPE                        DATA   AGE
allocatorw3secret     kubernetes.io/tls           2      29s
astraapiendpoint      Opaque                      1      28s
astraca               Opaque                      1      27s
astracqlhost          Opaque                      1      26s
astracreds            Opaque                      2      25s
astrakeyspace         Opaque                      1      24s
astratls              kubernetes.io/tls           2      23s
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
token-allocator-58c4cb5d68-rf78v   1/1     Running   0          3h53m
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
'''

If you have Python3 installed, run test.py to test the Astra database GraphQl endpoint and the endpoints of our service.
```
python3 test.py
```
