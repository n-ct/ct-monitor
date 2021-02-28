package main 

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"net/http"
	"time"
	"syscall"

	"github.com/golang/glog"
	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/monitor"
	"github.com/n-ct/ct-monitor/handler"

)

func main(){
	flag.Parse()
	defer glog.Flush()

	// Handle user interrupt to stop the Monitor 
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Initalize the variables of the Monitor
	monitorInstance, err := monitor.InitializeMonitor()
	if err != nil {
		glog.Infoln("Couldn't create monitor")
		glog.Flush()
		os.Exit(-1)
	}

	// Test the LoggerClient Interface
	monitorInstance.TestLogClient()

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
	server := &http.Server {
		Addr: m.ListenAddress,
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
func handlerSetup(m *monitor.Monitor) (*http.ServeMux) {
	handler := handler.NewHandler(m)
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(mtr.AuditPath, handler.Audit)
	serveMux.HandleFunc(mtr.NewInfoPath, handler.NewInfo)
	serveMux.HandleFunc(mtr.MonitorDomainPath, handler.MonitorDomain)

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

func shutdownServer(server *http.Server, returnCode int){
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	server.Shutdown(ctx)
	glog.Infoln("Shutting down Server")
	glog.Flush()
	os.Exit(returnCode)
}