package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocql/gocql"
)

//var apptoken string

// A handler for the web server
type handler func(w http.ResponseWriter, r *http.Request)

// The structure of the json response
type result struct {
	AppToken []string `json:"authToken"`
}

// Main will set up an http server and three endpoints
func main() {
	// Create it or append to the log file
	file, err := os.OpenFile("/home/servicee/logs/allocator-log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)

	// Serve 200 status on / for k8s health checks
	http.HandleFunc("/", handleRoot)

	// Serve 200 status on /healthz for k8s health checks
	http.HandleFunc("/healthz", handleHealthz)

	// Return the GameServerStatus of the allocated replica to the authorized client
	http.HandleFunc("/address", getOnly(basicAuth(handleAddress)))

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

// Let /address return the token
func handleAddress(w http.ResponseWriter, r *http.Request) {
	apptoken, err := allocate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&result{apptoken})
	if err != nil {
		log.Println("Error writing json from /address")
	}
}

// Generate a token and return it to the caller
func allocate() ([]string, error) {
	var cqlshrcHost = "6956bade-64fb-4dcd-9489-d3f836b92762-us-east1.db.astra.datastax.com"
	var cqlshrcPort = "31770"
	var username = "KVUser"
	var password = "KVPassword"
	//var clusterid = "6956bade-64fb-4dcd-9489-d3f836b92762"
	//var region = "us-east1"
	var apptoken []string

	certPath, _ := filepath.Abs("/home/trota/Code/cassandra/astra_gocql_connect/cert")
	keyPath, _ := filepath.Abs("/home/trota/Code/cassandra/astra_gocql_connect/key")
	caPath, _ := filepath.Abs("/home/trota/Code/cassandra/astra_gocql_connect/ca.crt")
	cert, _ := tls.LoadX509KeyPair(certPath, keyPath)
	caCert, _ := ioutil.ReadFile(caPath)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	cluster := gocql.NewCluster(cqlshrcHost)
	cluster.SslOpts = &gocql.SslOptions{
		Config:                 tlsConfig,
		EnableHostVerification: false,
	}
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: username,
		Password: password,
	}
	cluster.Hosts = []string{cqlshrcHost + ":" + cqlshrcPort}

	// generate a uuid
	// gocql.UUID also generates one... var id gocqlUUID
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Println("Error generating uuid")
	}
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	// fetch a graphql token from Astra, store it in resp
	client := &http.Client{}
	params := url.Values{}
	params.Set("username", username)
	params.Set("password", password)
	postData := strings.NewReader(params.Encode())
	req, err := http.NewRequest("POST", cqlshrcHost, postData)
	if err != nil {
		log.Println("Error building request")
	}
	req.Header.Add("x-cassandra-request-id", uuid)

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error fetching token from Datastax")
	}
	defer resp.Body.Close()
	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)
	apptoken = res["authToken"].([]string)

	// connect to the cluster
	session, err := cluster.CreateSession()
	if err != nil {
		log.Println("Error fetching token from Datastax")
	}
	defer session.Close()

	// get the session token from the db
	if err := session.Query(`UPDATE tribe_user_credentials SET app_token = ? WHERE email = ?`,
		uuid, "dogdogalina@mrdogdogalina.com").Exec; err != nil {
		log.Println("Error fetching token")
	}

	//fmt.Println("According to independent.co.uk, the top 2 most liveable cities in 2019 were:")
	//iter := session.Query(_query).Iter()
	//for iter.Scan(&_rank, &_city, &_country) {
	//	fmt.Printf("\tRank %d: %s, %s\n", _rank, _city, _country)
	//}
	//TODO: unmarshal resp and pass it as a string
	return apptoken, nil
}
