package monitor

import (
	"fmt"
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/golang/glog"
	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/entitylist"
	"github.com/n-ct/ct-monitor/utils"
	"github.com/n-ct/ct-monitor/signature"

	ctca "github.com/n-ct/ct-certificate-authority"
	ct "github.com/google/certificate-transparency-go"
)

type Monitor struct {
	LogIDMap map[string] *mtr.LogClient
	MonitorList	*entitylist.MonitorList
	GossiperURL string 
	ListenAddress string 
	CTObjectMap map[string]map[string]map[uint64]map[string] *mtr.CTObject
	Signer *signature.Signer
}

// Create a new Monitor using the createMonitor function found in monitor_setup.go
func NewMonitor(monitorConfigName string, monitorListName string, logListName string) (*Monitor, error){
	return createMonitor(monitorConfigName, monitorListName, logListName)
}

// Make a post request to corresponding GossiperURL with the given ctObject
func (m *Monitor) Gossip(ctObject *mtr.CTObject) error {
	jsonBytes, err := json.Marshal(ctObject)	// Just use serialize method somewhere else
	if err != nil {
		return fmt.Errorf("failed to marshal %s ctobject when gossiping: %v", ctObject.TypeID, err)
	}
	gossipURL := utils.CreateRequestURL(m.GossiperURL, "/ct/v1/gossip")
	glog.Infof("\ngossip CTObject using Gossiper at address: %s", gossipURL)

	// Create request
	req, err := http.NewRequest("POST", gossipURL, bytes.NewBuffer(jsonBytes)) 
	req.Header.Set("X-Custom-Header", "myvalue");
	req.Header.Set("Content-Type", "application/json");

	// Send request
	client := &http.Client{};
	resp, err := client.Do(req);
	if err != nil {
		panic(err);
	}

	defer resp.Body.Close();
	return nil
}

// Given STHCTObject, get stored corresponding STH and audit
func (m *Monitor) AuditSTH(ctObject *mtr.CTObject) (*mtr.CTObject, error) {
	var auditResp *mtr.CTObject
	storedSTH, err := m.GetCorrespondingSTHEntry(ctObject)
	if err != nil {
		return nil, fmt.Errorf("no corresponding STH in monitor to audit: %w", err)
	}

	// Compare the Digests of the two STHs
	if !bytes.Equal(storedSTH.Digest, ctObject.Digest){
		auditResp, err = mtr.CreateConflictingSTHPOM(storedSTH, ctObject) 
		if err != nil {
			return nil, fmt.Errorf("failed to create PoM during audit: %w", err)
		}
	} else {
		auditResp, err = mtr.CreateAuditOK(m.Signer, ctObject)
		if err != nil {
			return nil, fmt.Errorf("failed to create AuditOK during audit: %w", err)
		}
	}
	return auditResp, nil
}

// TODO Add support for alert ctObjects
// TODO Think about this logic a little more
func (m *Monitor) GetEntry(identifier mtr.ObjectIdentifier) *mtr.CTObject {
	return m.CTObjectMap[identifier.First][identifier.Second][identifier.Third][identifier.Fourth]
}

// Get STH with the given STHCTObject identifer stored within the monitor
// Returns normal STHCTObject even from STH_POC stored in monitor
func (m *Monitor) GetCorrespondingSTHEntry(ctObject *mtr.CTObject) (*mtr.CTObject, error) {
	id := ctObject.Identifier()
	sth := m.GetEntry(id)
	if sth == nil {
		id.First = mtr.STHPOCTypeID
		pocSTH := m.GetEntry(id)
		baseSTH, err := pocSTH.DeconstructSTH()
		if err != nil {
			return nil, fmt.Errorf("failed to getSTH from monitor map: %w", err)
		}
		sth, err = mtr.ConstructCTObject(baseSTH)
		if err != nil {
			return nil, fmt.Errorf("failed to getSTH from monitor map: %w", err)
		}
	}
	return sth, nil
}

//addEntry adds a new entry to the selected map using the data identifier as keys
// TODO Add error case here and in Identifier within types.go
func (m *Monitor) AddEntry(ctObject *mtr.CTObject) error {
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

// Temporary function to test basic monitor methods
func (m *Monitor) TestLogClient(){
	ctx := context.Background()
	logID := "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM="
	logClient := m.LogIDMap[logID]

	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		fmt.Printf("Failed to get STH from LogClient: %v", err)
		return;
	}
	fmt.Println(sth)

	//dSTH, err := sth.DeconstructSTH()
	//testSRDCTObj(dSTH.Signature)
}

func testCAList() {
	caList, err := entitylist.NewCAList("entitylist/ca_list.json")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(caList.FindCAByCAID("LeYXK29QzQV9RxvgMw+hnOeyZV85A6a5quOLltev9H0="))
	fmt.Println(caList.FindCAByCAURL("http://localhost:6000"))

}

func testSRDCTObj(sig ct.DigitallySigned) {
	crv := ctca.CreateCRV([]uint64{1,2}, 0)
	compCRV, err := ctca.CompressCRV(crv)
	if err != nil {
		fmt.Println(err)
	}
	revData := mtr.RevocationData{"hi", "hi", 3, compCRV}
	hsh := []byte("hi")
	revDigest := mtr.RevocationDigest{3, hsh, hsh}
	srd := mtr.SignedRevocationDigest{"ca", revDigest, sig}
	srdWithRev := mtr.SRDWithRevData{revData, srd}

	ctObj, err := mtr.ConstructCTObject(&srdWithRev)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ctObj)
}
