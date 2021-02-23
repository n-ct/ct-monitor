package monitor

import (
	"context"
	"fmt"
	"encoding/json"
	"net/http"
	"bytes"

	mtr "ct-monitor"
	"ct-monitor/entitylist"
	"ct-monitor/utils"
	//"ct-monitor/signature"
)

var (
	monitorConfigName = "monitor_config.json"
	monitorListName = "entitylist/monitor_list.json"
	logListName = "entitylist/log_list.json"
)

type Monitor struct {
	LogIDMap map[string] *mtr.LogClient
	MonitorList	*entitylist.MonitorList
	GossiperURL string 
	ListenAddress string 
	CTObjectMap map[string]map[string]map[uint64]map[string] *mtr.CTObject
	// TODO add a Signer that stores the private key and does all signing functionality
}

type MonitorConfig struct {
	LogIDs []string
	MonitorID string
}

func InitializeMonitor() (*Monitor, error){
	logIDMap, monitorList, gossiperURL, monitorURL, err := monitorSetupWithConfig()
	if err != nil {
		return nil, fmt.Errorf("Failed to create logClient")
	}
	ctObjectMap := make(map[string]map[string]map[uint64]map[string] *mtr.CTObject)
	monitor := &Monitor{logIDMap, monitorList, *gossiperURL, *monitorURL, ctObjectMap}
	return monitor, nil
}

// Initializes the various Monitor variables
func monitorSetupWithConfig() (map[string] *mtr.LogClient, *entitylist.MonitorList, *string, *string, error) {
	logIDMap := make(map[string] *mtr.LogClient)

	// Parse monitorConfig json
	byteData := utils.JSONFiletoBytes(monitorConfigName)
	var monitorConfig MonitorConfig
	if err := json.Unmarshal(byteData, &monitorConfig); err != nil {
		return logIDMap, nil, nil, nil, fmt.Errorf("failed to parse log list: %v", err)
	}

	// Create logIDMap
	logList := entitylist.NewLogList(logListName)
	for _, logID := range monitorConfig.LogIDs {
		log := logList.FindLogByLogID(logID)
		logClient, err := mtr.NewLogClient(log)
		if err != nil {
			fmt.Printf("Failed to create logClient")
			return logIDMap, nil, nil, nil, fmt.Errorf("Failed to create logClient")
		}
		logIDMap[logID] = logClient
	}

	// Create MonitorList get GossiperURL
	monitorList := entitylist.NewMonitorList(monitorListName)
	monitorInfo := monitorList.FindMonitorByMonitorID(monitorConfig.MonitorID)
	gossiperURL := &monitorInfo.GossiperURL
	monitorURL := &monitorInfo.MonitorURL
	return logIDMap, monitorList, gossiperURL, monitorURL, nil
}

// Make a post request to corresponding GossiperURL with the given ctObject
func (m *Monitor) Gossip(ctObject mtr.CTObject) {
	jsonBytes, _ := json.Marshal(ctObject)
	gossipURL := utils.CreateRequestURL(m.GossiperURL, "/gossip")
	req, err := http.NewRequest("POST", gossipURL, bytes.NewBuffer(jsonBytes)) 
	req.Header.Set("X-Custom-Header", "myvalue");
	req.Header.Set("Content-Type", "application/json");

	client := &http.Client{};
	resp, err := client.Do(req);
	if err != nil {
		panic(err);
	}

	defer resp.Body.Close();
}

//addEntry adds a new entry to the selected map using the data identifier as keys
func (m *Monitor) AddEntry(ctObject *mtr.CTObject){
	identifier := ctObject.Identifier()

	if _, ok := m.CTObjectMap[identifier.First]; !ok {
		m.CTObjectMap[identifier.First] = make(map[string]map[uint64]map[string] *mtr.CTObject);
	}
	if _, ok := m.CTObjectMap[identifier.First][identifier.Second]; !ok {
		m.CTObjectMap[identifier.First][identifier.Second] = make(map[uint64]map[string] *mtr.CTObject);
	}
	if _, ok := m.CTObjectMap[identifier.First][identifier.Second][identifier.Third]; !ok {
		m.CTObjectMap[identifier.First][identifier.Second][identifier.Third] = make(map[string] *mtr.CTObject);
	}
	m.CTObjectMap[identifier.First][identifier.Second][identifier.Third][identifier.Fourth] = ctObject;
}

// Temporary function to test basic loggerClient methods
func (m *Monitor) TestLogClient(){
	ctx := context.Background()
	logID := "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM="
	logClient := m.LogIDMap[logID]
	sth, err := logClient.GetSTHWithConsistencyProof(ctx, 100, 1000)
	if err != nil {
		fmt.Printf("Failed to create STH")
		return;
	}

	fmt.Println(sth)
	fmt.Println()

	monitorList := entitylist.NewMonitorList(monitorListName)
	fmt.Println(monitorList)
	monitorID := "mid"
	fmt.Println(monitorList.FindMonitorByMonitorID(monitorID))

	fmt.Println()
	fmt.Println(m.CTObjectMap)
	m.AddEntry(sth)
	fmt.Println(m.CTObjectMap)

	fmt.Println()
	fmt.Println(utils.CreateRequestURL("localhost:8080/", "/gossip"))

}
