package monitor

import (
	"testing"
)

var (
	monitorConfigName = "monitor_config.json"
	monitorListName = "../entitylist/monitor_list.json"
	logListName = "../entitylist/log_list.json"
)

func mustGetMonitor(t *testing.T) (*Monitor, error) {
	t.Helper()
	return NewMonitor(monitorConfigName, monitorListName, logListName)
}

func TestNewMonitor(t *testing.T) {
	_, err := mustGetMonitor(t)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestAuditSTH(t *testing.T) {
	//monitor, _ := mustGetMonitor(t)

}

func TestGetEntry(t *testing.T) {

}

func TestGetCorrespondingSTHEntry(t *testing.T) {

}

func TestAddEntry(t *testing.T) {

}
