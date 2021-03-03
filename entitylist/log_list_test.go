package entitylist

import (
	"testing"
)

const (
	logListPath = "log_list.json"
	testLogID = "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM="
	testLogIDKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw=="
)

func mustCreateLogList(t *testing.T) (*LogList, error) {
	t.Helper()
	return NewLogList(logListPath)
}

func TestNewLogList(t *testing.T) {
	_, err := mustCreateLogList(t)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestFindLogByLogID(t *testing.T) {
	logList, _ := mustCreateLogList(t)
	logInfo := logList.FindLogByLogID(testLogID)
	if logInfo == nil {
		t.Fatalf("testLogID (%s) not found in %s", testLogID, logListPath)
	}

	if logInfo.Key != testLogIDKey {
		t.Fatalf("received wrong log from testLogID (%s): %v", testLogID, logInfo)
	}
}


