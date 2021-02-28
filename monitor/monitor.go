package monitor

import (
	"context"
	"fmt"
	"encoding/json"
	"net/http"
	"bytes"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/entitylist"
	"github.com/n-ct/ct-monitor/utils"
	"github.com/n-ct/ct-monitor/signature"
)

var (
	monitorConfigName = "monitor/monitor_config.json"
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
	Signer *signature.Signer
}

type MonitorConfig struct {
	LogIDs []string `json:"logIDs"`
	MonitorID string `json:"monitorID"`
	StrPrivKey string `json:"privKey"`
}

func InitializeMonitor() (*Monitor, error){
	logIDMap, monitorList, gossiperURL, monitorURL, signer, err := monitorSetupWithConfig()
	if err != nil {
		return nil, fmt.Errorf("Failed to create logClient")
	}
	ctObjectMap := make(map[string]map[string]map[uint64]map[string] *mtr.CTObject)
	monitor := &Monitor{logIDMap, monitorList, *gossiperURL, *monitorURL, ctObjectMap, signer}
	return monitor, nil
}


// Initializes the various Monitor variables
func monitorSetupWithConfig() (map[string] *mtr.LogClient, *entitylist.MonitorList, *string, *string, *signature.Signer, error) {
	logIDMap := make(map[string] *mtr.LogClient)

	// Parse monitorConfig json
	byteData := utils.JSONFiletoBytes(monitorConfigName)
	var monitorConfig MonitorConfig
	if err := json.Unmarshal(byteData, &monitorConfig); err != nil {
		return logIDMap, nil, nil, nil, nil, fmt.Errorf("failed to parse log list: %v", err)
	}

	// Create logIDMap
	logList := entitylist.NewLogList(logListName)
	for _, logID := range monitorConfig.LogIDs {
		log := logList.FindLogByLogID(logID)
		logClient, err := mtr.NewLogClient(log)
		if err != nil {
			fmt.Printf("Failed to create logClient")
			return logIDMap, nil, nil, nil, nil, fmt.Errorf("Failed to create logClient")
		}
		logIDMap[logID] = logClient
	}

	// Get PrivateKey from config file for testing
	strPrivKey := monitorConfig.StrPrivKey
	fmt.Println()
	fmt.Println()
	fmt.Println(monitorConfig)
	fmt.Println()
	fmt.Println()
	// TODO ADD error logic here
	signer := signature.NewSigner(strPrivKey)

	// Create MonitorList and get GossiperURL
	monitorList := entitylist.NewMonitorList(monitorListName)
	monitorInfo := monitorList.FindMonitorByMonitorID(monitorConfig.MonitorID)
	gossiperURL := &monitorInfo.GossiperURL
	monitorURL := &monitorInfo.MonitorURL
	return logIDMap, monitorList, gossiperURL, monitorURL, signer, nil
}

// Make a post request to corresponding GossiperURL with the given ctObject
func (m *Monitor) Gossip(ctObject *mtr.CTObject) {
	jsonBytes, _ := json.Marshal(ctObject)
	gossipURL := utils.CreateRequestURL(m.GossiperURL, "/ct/v1/gossip")
	fmt.Printf("\ngossip CTObject using Gossiper at address: %s", gossipURL)
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

// TODO Add error handling
// TODO Add sending PoM as resp. Currently only send audit-ok. NEED TO REFACTOR
func (m *Monitor) AuditSTH(ctObject *mtr.CTObject) *mtr.CTObject {
	id := ctObject.Identifier()
	var baseSTH mtr.SignedTreeHeadData
	// TODO Add function to get sth from storage (does the check for both sth_poc and sth)
	sth := m.GetEntry(id)
	if sth == nil {
		id.First = mtr.STHPOCTypeID
		poc_sth := m.GetEntry(id)
		baseSTH = *mtr.ExtractSTHFromSTHPOCCTObject(poc_sth)
	} else {
		baseSTH = mtr.DeconstructCTObject(sth).(mtr.SignedTreeHeadData)
	}

	var auditResp *mtr.CTObject
	auditResp, _ = mtr.CreateAuditOK(m.Signer, &baseSTH)
	return auditResp
}

// TODO Add support for alert ctObjects
func (m *Monitor) GetEntry(identifier mtr.ObjectIdentifier) *mtr.CTObject {
	return m.CTObjectMap[identifier.First][identifier.Second][identifier.Third][identifier.Fourth]
}

//addEntry adds a new entry to the selected map using the data identifier as keys
// TODO Add error case here and in Identifier within types.go
func (m *Monitor) AddEntry(ctObject *mtr.CTObject) error{
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
	return nil
}

// Temporary function to test basic loggerClient methods
func (m *Monitor) TestLogClient(){
	ctx := context.Background()
	logID := "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM="
	logClient := m.LogIDMap[logID]

	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		fmt.Printf("Failed to create STH")
		return;
	}
	//m.Gossip(sth)

	sth1, err := logClient.GetSTH(ctx)
	if err != nil {
		fmt.Printf("Failed to create STH1")
		return;
	}
	fmt.Println(sth)
	fmt.Println()
	fmt.Println(sth1)

	/*sth_poc, err := logClient.GetSTHWithConsistencyProof(ctx, 100, 1000)
	if err != nil {
		fmt.Printf("Failed to create STH1")
		return;
	}

	fmt.Println()
	fmt.Println(m.CTObjectMap)
	m.AddEntry(sth_poc)
	fmt.Println(m.CTObjectMap)

	ext_sth := mtr.ExtractSTHFromSTHPOCCTObject(sth_poc)
	id := mtr.ConstructCTObject(ext_sth).Identifier()
	id.First = mtr.STHPOCTypeID
	fmt.Println()
	fmt.Println(m.GetEntry(id))
	*/
}
