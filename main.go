package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gocql/gocql"
)

//var apptoken string

// A handler for the web server
type handler func(w http.ResponseWriter, r *http.Request)

// The structure of the json response
type result struct {
	AppToken  string `json:"authToken"`
	RequestID string `json:"requestID"`
}

// The structure of the payload we send to Astra
//type credentials struct {
//	Username string `json:"username"`
//	Password string `json:"password"`
//}

// Main will set up an http server and three endpoints
func main() {
	// Create or append to the log file
	file, err := os.OpenFile("/home/service/logs/allocator-log.txt",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	} else {
		log.SetOutput(file)
		log.Println("Started logging")
	}

	// Serve 200 status on / for k8s health checks
	http.HandleFunc("/", handleRoot)

	// Serve 200 status on /healthz for k8s health checks
	http.HandleFunc("/healthz", handleHealthz)

	// Return the Astra GraphQL token from Datastax
	http.HandleFunc("/authToken", getOnly(basicAuth(handleToken)))

	// Run the HTTP server using the bound certificate and key for TLS
	if err := http.ListenAndServeTLS(":8000", "/home/service/certs/tls.crt", "/home/service/certs/tls.key", nil); err != nil {
		log.Println("HTTPS server failed to run")
	} else {
		log.Println("HTTPS server is running on port 8000")
	}
}

// Limit verbs the web server handles
func getOnly(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			h(w, r)
			return
		}
		http.Error(w, "Get Only", http.StatusMethodNotAllowed)
	}
}

// Let the web server do basic authentication
func basicAuth(pass handler) handler {
	return func(w http.ResponseWriter, r *http.Request) {
		key, value, _ := r.BasicAuth()
		if key != "v1GameClientKey" || value != "EAEC945C371B2EC361DE399C2F11E" {
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}
		pass(w, r)
	}
}

// Let / return Healthy and status code 200
func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := io.WriteString(w, "Healthy")
	if err != nil {
		log.Println("Error writing string Healthy from /")
	}
}

// Let /healthz return Healthy and status code 200
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := io.WriteString(w, "Healthy")
	if err != nil {
		log.Println("Error writing string Healthy from /healthz")
	}
}

// Let /authToken return the token
func handleToken(w http.ResponseWriter, r *http.Request) {
	apptoken, uuid, err := fetchToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&result{apptoken, uuid})
	if err != nil {
		log.Println("Error writing json from /authToken")
	}
}

// Fetch the token and from Astra
// fetch a graphql token from Astra api, store it in resp
// TODO: create a transport and use it in the client
// TODO: make this it's own function
// https://golang.org/pkg/net/http/
func fetchToken() (string, string, error) {
	var username = "KVUser"
	var password = "KVPassword"
	var apiEndpoint = "https://6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.apps.astra.datastax.com/api/rest/v1/auth"
	//var clusterid = "6956bade-64fb-4dcd-9489-d3f836b92762"
	//var region = "us-east1"
	var apptoken string
	//var jsonData []byte

	// generate a uuid
	// gocql.UUID also generates one... var id gocqlUUID
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Println("Error generating uuid")
	}
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	client := &http.Client{Transport: tr}

	var jsonData = []byte(`{"username":"` + username + `","password":"` + password + `"}`)
	//var jsonData = []byte(`"username":"` + username + `","password":"` + password + `"`)
	req, err := http.NewRequest("POST", apiEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Error building request")
	} else {
		log.Println("Request created successfully")
		log.Println("Request apiEndpoint: ", apiEndpoint)
		log.Println("Request jsonData: ", jsonData)
	}
	req.Header.Set("accept", "*/*")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-cassandra-request-id", uuid)
	if err != nil {
		log.Println("Error adding headers")
	} else {
		log.Println("Set headers")
		//Loop over header names
		for name, values := range req.Header {
			//Loop over all values for the name.
			for _, value := range values {
				log.Println("Header name, value: ", name, value)
			}
		}
	}

	//buf, bodyErr := ioutil.ReadAll(req.Body)
	//if bodyErr != nil {
	//	log.Println("bodyErr ", bodyErr.Error())
	//} else {
	//	log.Println("Body created successfully")
	//}

	resp, err := client.Do(req)
	if err != nil {
		//log.Println("The uuid: ", uuid)
		//log.Println("The request data: ", ioutil.NopCloser(bytes.NewBuffer(buf)))
		log.Println("Error fetching token from Datastax")
		log.Println("Error: ", err)
	}

	log.Println("response Status:", resp.Status)
	log.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	log.Println("response Body:", string(body))

	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)
	apptoken = res["authToken"].(string)

	resp.Body.Close()

	//return the x-cassandra-token and x-cassandra-request-id values
	return apptoken, uuid, nil
}

// Generate a token and return it to the caller
// Send this to get the x-cassandra-token
//	curl --request POST \
//	  --url https://${ASTRA_CLUSTER_ID}-${ASTRA_CLUSTER_REGION}.apps.astra.datastax.com/api/rest/v1/auth \
//	  --header 'accept: */*' \
//	  --header 'content-type: application/json' \
//	  --header 'x-cassandra-request-id: {unique-UUID}' \
//	  --data '{"username":"'"${ASTRA_DB_USERNAME}"'", "password":"'"${ASTRA_DB_PASSWORD}"'"}'

// Return the request-id and token to the caller so they can use it to log in
//curl --request GET \
//--url https://${ASTRA_CLUSTER_ID}-${ASTRA_CLUSTER_REGION}.apps.astra.datastax.com/api/rest/v1/keyspaces \
//--header 'accept: application/json' \
//--header 'x-cassandra-request-id: 3d9a5582-b5d9-401a-bfcc-9fc4c915d4a8' \
//--header "x-cassandra-token: aa5fe743-a764-47a2-9f3b-8467545593b4"

// Write the request-id and token to the user credentials table
func allocate(username string, password string, uuid string) error {
	log.Println("begining of allocate")
	var cqlshrcHost = "6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.db.astra.datastax.com"
	var cqlshrcPort = "31770"

	// set up the connection
	certPath, _ := filepath.Abs("/home/service/astracerts/tls.crt")
	keyPath, _ := filepath.Abs("/home/service/astracerts/tls.key")
	caPath, _ := filepath.Abs("/home/service/astraca/astraca")
	cert, _ := tls.LoadX509KeyPair(certPath, keyPath)
	caCert, _ := ioutil.ReadFile(caPath)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	cluster := gocql.NewCluster(cqlshrcHost)
	cluster.Timeout = time.Second * 30
	cluster.Keyspace = "killrvideo"
	cluster.Consistency = gocql.One
	cluster.SslOpts = &gocql.SslOptions{
		Config:                 tlsConfig,
		EnableHostVerification: false,
	}
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: username,
		Password: password,
	}
	cluster.Hosts = []string{cqlshrcHost + ":" + cqlshrcPort}

	// connect to the cluster
	session, err := cluster.CreateSession()
	if err != nil {
		log.Println("Error creating session")
	} else {
		log.Println("Session created successfully")
	}
	defer session.Close()

	// update the user credentials record with the token
	if err := session.Query(`UPDATE tribe_user_credentials SET app_token = ? WHERE email = ?`,
		uuid, "dogdogalina@mrdogdogalina.com").Exec; err != nil {
		log.Println("Error fetching token")
	}
	return nil
}
