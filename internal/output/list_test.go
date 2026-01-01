package output

import (
	"encoding/json"
	"testing"
)

func TestStoreList_FormatJSON_Fields(t *testing.T) {
	list := &StoreList{
		Entries: []ListEntry{
			{Platform: "ios", Version: "18", Fingerprint: "AA:BB:CC:DD", Issuer: "Test CA"},
		},
	}

	data, err := list.FormatJSON()
	if err != nil {
		t.Fatal(err)
	}

	var parsed []map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	entry := parsed[0]
	if entry["platform"] != "ios" {
		t.Errorf("platform = %v, want ios", entry["platform"])
	}
	if entry["version"] != "18" {
		t.Errorf("version = %v, want 18", entry["version"])
	}
	if entry["fingerprint"] != "AA:BB:CC:DD" {
		t.Errorf("fingerprint = %v, want AA:BB:CC:DD", entry["fingerprint"])
	}
	if entry["issuer"] != "Test CA" {
		t.Errorf("issuer = %v, want Test CA", entry["issuer"])
	}
}

func TestStoreList_FormatJSON_Empty(t *testing.T) {
	list := &StoreList{
		Entries: []ListEntry{},
	}

	data, err := list.FormatJSON()
	if err != nil {
		t.Fatal(err)
	}

	// Empty list should produce empty JSON array
	if string(data) != "[]" {
		t.Errorf("empty list should produce [], got: %s", string(data))
	}
}

func TestStoreList_FormatJSON_ConstraintsPresent(t *testing.T) {
	list := &StoreList{
		Entries: []ListEntry{
			{Platform: "chrome", Version: "current", Fingerprint: "AA:BB:CC:DD", Issuer: "Buypass", Constraints: "SCT:2025-10-31"},
		},
	}

	data, err := list.FormatJSON()
	if err != nil {
		t.Fatal(err)
	}

	var parsed []map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	entry := parsed[0]
	if entry["constraints"] != "SCT:2025-10-31" {
		t.Errorf("constraints = %v, want SCT:2025-10-31", entry["constraints"])
	}
}
