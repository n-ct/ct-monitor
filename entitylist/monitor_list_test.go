package entitylist

import (
	"testing"
)

const (
	monitorListPath = "../testdata/monitor_list.json"
	testMonitorID = "monitor1"
	testMonitorIDKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2HQc8jcuoOj/H/4+HQItNBEolurr547rC5i4O61Wf0mxvV9anHz+kIcTy7n9hnStoK+WGkI3fF6k7l2IO3OiyA=="
	testMonitorIDURL = "localhost:8080"
)

func mustCreateMonitorList(t *testing.T) (*MonitorList, error) {
	t.Helper()
	return NewMonitorList(monitorListPath)
}

func TestNewMonitorList(t *testing.T) {
	_, err := mustCreateMonitorList(t)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestFindMonitorByMonitorID(t *testing.T) {
	monitorList, _ := mustCreateMonitorList(t)
	monitorInfo := monitorList.FindMonitorByMonitorID(testMonitorID)
	if monitorInfo == nil {
		t.Fatalf("testMonitorID (%s) not found in %s", testMonitorID, monitorListPath)
	}

	if monitorInfo.MonitorKey != testMonitorIDKey {
		t.Fatalf("received wrong monitor from testMonitorID (%s): %v", testMonitorID, monitorInfo)
	}
}

func TestFindMonitorByMonitorURL(t *testing.T) {
	monitorList, _ := mustCreateMonitorList(t)
	monitorInfo := monitorList.FindMonitorByMonitorURL(testMonitorIDURL)
	if monitorInfo == nil {
		t.Fatalf("testMonitorIDURL (%s) not found in %s", testMonitorIDURL, monitorListPath)
	}

	if monitorInfo.MonitorKey != testMonitorIDKey {
		t.Fatalf("received wrong monitor from testMonitorIDURL (%s): %v", testMonitorIDURL,  monitorInfo)
	}
}