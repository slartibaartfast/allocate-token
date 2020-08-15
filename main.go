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
//TODO: differentiate between incorrect creds and no account matching the username
//TODO: move adminusername and adminpassword to secrets
var adminusername = "KVUser"
var adminpassword = "KVPassword"

var email string
var count string

//TODO:  move apiEndpoint to secrets
var apiEndpoint = "https://6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.apps.astra.datastax.com/api/rest/v1/auth"
var session *gocql.Session

func init() {
	//TODO:  move cqlshrcHost to secrets
	var cqlshrcHost = "6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.db.astra.datastax.com"
	var cqlshrcPort = "31770"

	// set up the connection
	certPath, err := filepath.Abs("/home/service/astracerts/tls.crt")
	if err != nil {
		log.Println("Error with certPath")
		log.Println(err)
	}
	keyPath, err := filepath.Abs("/home/service/astracerts/tls.key")
	if err != nil {
		log.Println("Error with keyPath")
		log.Println(err)
	}
	caPath, _ := filepath.Abs("/home/service/astraca/astraca")
	if err != nil {
		log.Println("Error with caPath")
		log.Println(err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Println("Error loading cert key pair")
		log.Println(err)
	}
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Println("Error reading ca")
		log.Println(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	cluster := gocql.NewCluster(cqlshrcHost)
	cluster.Timeout = time.Second * 30
	//TODO: move Keyspace to secrets
	cluster.Keyspace = "killrvideo"
	cluster.Consistency = gocql.Quorum
	cluster.SslOpts = &gocql.SslOptions{
		Config:                 tlsConfig,
		EnableHostVerification: false,
	}
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: adminusername,
		Password: adminpassword,
	}
	cluster.Hosts = []string{cqlshrcHost + ":" + cqlshrcPort}

	// create a session
	session, err = cluster.CreateSession()
	if err != nil {
		log.Println("Error creating session")
		log.Println(err)
	} else {
		log.Println("Session created successfully")
	}
	fmt.Println("Astra init done")
}

// A handler for the web server
type handler func(w http.ResponseWriter, r *http.Request)

// The structure of the json response from Astra
// {"authToken":"74b98a80-7150-48b6-92b9-f0e58161b368"}
type astraResponse struct {
	AuthToken string `json:"authToken"`
}

// The structure of our json response
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

	// defer closing the session
	defer session.Close()

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
		username, password, _ := r.BasicAuth()
		log.Println("basic auth username: ", username)
		log.Println("basic auth password: ", password)
		// check to see if the user exists
		count := checkUsername(username)
		if count != 1 {
			http.Error(w, "nonexistant username", http.StatusNotFound)
			return
		}
		// validate the username and password
		err := validateUser(username, password)
		if err != nil {
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
	authToken, requestID, err := fetchToken()
	log.Println("handleToken authToken:", authToken)
	log.Println("handlToken requestID:", requestID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&result{authToken, requestID})
	if err != nil {
		log.Println("Error writing json from /authToken")
	} else {
		// write the requestID to the caller's credentials table
		email, password, _ := r.BasicAuth()
		err = writeToDB(authToken, requestID, email, password)
	}
}

// See if this username exists
func checkUsername(username string) int {
	var count int
	if err := session.Query(
		`SELECT count(*()) FROM tribe_user_credentials WHERE email = ?`,
		username).Scan(&count); err != nil {
		log.Println("Error validating user")
		log.Println(err)
		return 0
	}

	return count
}

// Validate the received user credentials against the stored user credentials
func validateUser(username string, password string) error {
	log.Println("begining of validateUser")
	var userID string

	// Select a user with the supplied credentials
	if err := session.Query(
		`SELECT user_id FROM tribe_user_credentials WHERE email = ? and password = ?`,
		username, password).Scan(&userID); err != nil {
		log.Println("Error validating user")
		log.Println(err)
		return err
	}
	return nil
}

// fetch a graphql api token from Astra api, return the token and a uuid
func fetchToken() (string, string, error) {
	//var username = "KVUser"
	//var password = "KVPassword"
	//var apiEndpoint = "https://6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.apps.astra.datastax.com/api/rest/v1/auth"
	var apptoken = new(astraResponse)

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

	var jsonData = []byte(`{"username":"` + adminusername + `","password":"` + adminpassword + `"}`)
	req, err := http.NewRequest("POST", apiEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Error building request")
		log.Println("Error: ", err)
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

	err = json.Unmarshal(body, &apptoken)
	if err != nil {
		log.Println("Error unmarshalling")
		log.Println(err)
	}

	resp.Body.Close()

	//return the x-cassandra-token and x-cassandra-request-id values
	return apptoken.AuthToken, uuid, err
}

// Write the request-id and token to the user credentials table
//TODO: upsert the current time to date_creds_generated
func writeToDB(authToken string, uuid string, email string, password string) error {
	if err := session.Query(
		`UPDATE tribe_user_credentials SET app_token = ?, app_request_id = ? WHERE email = ?`,
		authToken, uuid, email).Exec(); err != nil {
		log.Println("Error updating tribe_user_credentials with token, uuid")
		log.Println(err)
	}
	return nil
}
