package monitor

import (
	"fmt"
	"strings"
	"encoding/json"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/entitylist"
	"github.com/n-ct/ct-monitor/utils"
	"github.com/n-ct/ct-monitor/signature"
)

// Create Monitor 
func createMonitor(monitorConfigName string, monitorListName string, logListName string) (*Monitor, error){
	monitorConfig, err := parseMonitorConfig(monitorConfigName)
	if nil != err {
		return nil, fmt.Errorf("failed to setup new monitor: %w", err)
	}
	logIDMap, err := createLogIDMap(monitorConfig, logListName)
	if nil != err {
		return nil, fmt.Errorf("failed to setup new monitor: %w", err)
	}
	signer, err := createSigner(monitorConfig)
	if nil != err {
		return nil, fmt.Errorf("failed to setup new monitor: %w", err)
	}
	monitorList, gossiperURL, monitorURL, err := getMonitorListInfo(monitorListName, monitorConfig)
	if nil != err {
		return nil, fmt.Errorf("failed to setup new monitor: %w", err)
	}
	ctObjectMap := make(map[string]map[string]map[uint64]map[string] *mtr.CTObject)
	monitor := &Monitor{logIDMap, monitorList, *gossiperURL, *monitorURL, ctObjectMap, signer}
	return monitor, nil
}

// Stores the contents of monitor_config.json
type MonitorConfig struct {
	LogIDs []string `json:"logIDs"`
	MonitorID string `json:"monitorID"`
	StrPrivKey string `json:"privKey"`
}

// Parse monitorConfig json file 
func parseMonitorConfig(monitorConfigName string) (*MonitorConfig, error) {
	byteData, err := utils.FiletoBytes(monitorConfigName)
	if err != nil {
		return nil, fmt.Errorf("error parsing monitor config: %w", err)
	}
	var monitorConfig MonitorConfig
	err = json.Unmarshal(byteData, &monitorConfig) 
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal monitor config: %w", err)
	}
	return &monitorConfig, nil
}

// Create a map of logger LogIDs to their corresponding LogClients
func createLogIDMap(monitorConfig *MonitorConfig, logListName string) (map[string] *mtr.LogClient, error) {
	logIDMap := make(map[string] *mtr.LogClient)
	logList, err := entitylist.NewLogList(logListName)
	if err != nil {
		return nil, fmt.Errorf("failed to create loglist for logIDMap: %w", err)
	}

	// Iterate through all the LogIDs within monitorConfig and add them to map along with their created logclients
	for _, logID := range monitorConfig.LogIDs {
		log := logList.FindLogByLogID(logID)
		logClient, err := mtr.NewLogClient(log)
		if err != nil {
			return nil, fmt.Errorf("failed to create logClient for logIDMap: %w", err)
		}
		logIDMap[logID] = logClient
	}
	return logIDMap, nil 
}

// Create signer for the Monitor
func createSigner(monitorConfig *MonitorConfig) (*signature.Signer, error) {
	strPrivKey := monitorConfig.StrPrivKey
	signer, err := signature.NewSigner(strPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer in monitor: %w", err)
	}
	return signer, nil
}

// Get MonitorList info from monitorList
func getMonitorListInfo(monitorListName string, monitorConfig *MonitorConfig) (*entitylist.MonitorList, *string, *string, error) {
	monitorList, err := entitylist.NewMonitorList(monitorListName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating monitor list for monitor config: %w", err)
	}
	monitorInfo := monitorList.FindMonitorByMonitorID(monitorConfig.MonitorID)
	gossiperURL := &monitorInfo.GossiperURL
	msplit := strings.Split(monitorInfo.MonitorURL, ":")
	monitorURL := msplit[1][2:] + ":" + msplit[2]
	return monitorList, gossiperURL, &monitorURL, nil
}