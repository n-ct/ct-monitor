package main 

import (
	"context"
	"fmt"
	"flag"
	"os"
	"os/signal"
	"net/http"
	"time"
	"github.com/golang/glog"
	"encoding/json"

	mtr "ct-monitor"
	"ct-monitor/loglist"
	"ct-monitor/utils"
)

var (
	listenAddress = flag.String("listen", ":8080", "Listen address:port for HTTP server")
	monitorConfigName = "monitor_config.json"
	logIDMap = map[string] *mtr.LogClient{}
)

type MonitorConfig struct {
	LogIDs []string
}

func main(){
	flag.Parse()
	defer glog.Flush()

	// Handle user interrupt to stop the Monitor 
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Initalize the variables of the Monitor
	monitorSetup()

	// Create http.Server instance for the Monitor
	server := serverSetup()
	glog.Infoln("Created monitor http.Server")

	// Test the LoggerClient Interface
	testLogClient()

	// Handling the stop signal and closing things 
	<-stop
	glog.Infoln("Received stop signal")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	server.Shutdown(ctx)
	glog.Infoln("Graceful shutdown")
	
}

// Initializes the various Monitor variables
func monitorSetup() {
	byteData := utils.JSONFiletoBytes(monitorConfigName)
	var monitorConfig MonitorConfig
	if err := json.Unmarshal(byteData, &monitorConfig); err != nil {
		fmt.Errorf("failed to parse log list: %v", err)
	}

	logList := loglist.NewLogList()
	for _, logID := range monitorConfig.LogIDs {
		log := logList.FindLogByLogID(logID)
		logClient, err := mtr.NewLogClient(log)
		if err != nil {
			fmt.Printf("Failed to create logClient")
			return;
		}
		logIDMap[logID] = logClient
	}
}

// Sets up the basic monitor http server
func serverSetup() *http.Server{
	serveMux := handlerSetup()
	server := &http.Server {
		Addr: *listenAddress,
		Handler: serveMux,
	}

	// start up handles
	go func() {
		if err := server.ListenAndServe(); err != nil {
		glog.Exitf("Problem serving: %v\n",err)
		}
	}()
	return server
}

// Sets up the handler and the various path handle functions
func handlerSetup() (*http.ServeMux) {
	handler := mtr.NewHandler()
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/new-ct/get-sth", handler.GetSth)	// Currently only exists for testing purposes

	// Return a 200 on the root so clients can easily check if server is up
	serveMux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			resp.WriteHeader(http.StatusOK)
		} else {
			resp.WriteHeader(http.StatusNotFound)
		}
	})
	return serveMux
}

// Temporary function to test basic loggerClient methods
func testLogClient(){
	ctx := context.Background()
	logID := "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM="	// Will replace the logID hardcode with loglist.go call
	logClient := logIDMap[logID]
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		fmt.Printf("Failed to create STH")
		return;
	}
	glog.Infoln(sth)

	poc, err := logClient.GetSTHConsistency(ctx, 100, 1000)
	if err != nil {
		fmt.Printf("Failed to get Entry and Proof")
		return;
	}
	fmt.Println(poc)	
}


