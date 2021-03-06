package main 

import (
	"fmt"
	"context"
	"time"
	"flag"
	"os"
	"os/signal"
	"net/http"
	"syscall"

	"github.com/golang/glog"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/monitor"
	"github.com/n-ct/ct-monitor/handler"
)

var (
	monitorConfigName = flag.String("config", "monitor/monitor_config.json", "File containing Monitor configuration")
	monitorListName = flag.String("monitorlist", "entitylist/monitor_list.json", "File containing MonitorList")
	logListName = flag.String("loglist", "entitylist/log_list.json", "File containing LogList")
)

func main(){
	flag.Parse()
	defer glog.Flush()

	// Handle user interrupt to stop the Monitor 
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Initalize the variables of the Monitor
	monitorInstance, err := monitor.NewMonitor(*monitorConfigName, *monitorListName, *logListName)
	if err != nil {
		fmt.Println("failed to create monitor: %w", err)	// Only for testing purposes
		glog.Fatalf("Couldn't create monitor: %v", err)
		glog.Flush()
		os.Exit(-1)
	}
	glog.Infoln("Starting CT-Monitor")

	// Test the LoggerClient Interface
	//monitorInstance.TestLogClient()

	// Create http.Server instance for the Monitor
	server := serverSetup(monitorInstance)
	glog.Infoln("Created monitor http.Server")

	// Handling the stop signal and closing things 
	<-stop
	glog.Infoln("Received stop signal")
	shutdownServer(server, 0)
}

// Sets up the basic monitor http server
func serverSetup(m *monitor.Monitor) *http.Server{
	serveMux := handlerSetup(m)
	glog.Infof("Serving at address: %s", m.ListenAddress)
	server := &http.Server {
		Addr: m.ListenAddress,
		Handler: serveMux,
	}

	// start up handles
	go func() {
		if err := server.ListenAndServe(); err != nil {
			glog.Flush()
			glog.Infof("Problem serving: %v\n",err)
		}
	}()
	return server
}

// Sets up the handler and the various path handle functions
func handlerSetup(m *monitor.Monitor) (*http.ServeMux) {
	handler := handler.NewHandler(m)
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(mtr.AuditPath, handler.Audit)
	serveMux.HandleFunc(mtr.NewInfoPath, handler.NewInfo)
	serveMux.HandleFunc(mtr.MonitorDomainPath, handler.MonitorDomain)
	serveMux.HandleFunc(mtr.STHGossipPath, handler.STHGossip)
	serveMux.HandleFunc(mtr.STHWithPOCGossipPath, handler.STHWithPOCGossip)
	serveMux.HandleFunc(mtr.SRDWithRevDataGossipPath, handler.SRDWithRevDataGossip)

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

// Shuts down the Monitor Server instance
func shutdownServer(server *http.Server, returnCode int){
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	server.Shutdown(ctx)
	glog.Infoln("Shutting down Server")
	glog.Flush()
	os.Exit(returnCode)
}