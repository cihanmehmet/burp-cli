package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ScanRecord represents a single scan record
type ScanRecord struct {
	ScanID      string    `json:"scan_id"`
	URL         string    `json:"url"`
	StartTime   time.Time `json:"start_time"`
	Status      string    `json:"status"`
	ConfigName  string    `json:"config_name,omitempty"`
	ScanName    string    `json:"scan_name,omitempty"`
	LastChecked time.Time `json:"last_checked,omitempty"`
}

// ScanTracker manages scan records
type ScanTracker struct {
	Records []ScanRecord `json:"records"`
	filePath string
}

// NewScanTracker creates a new scan tracker
func NewScanTracker() (*ScanTracker, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %v", err)
	}
	
	configDir := filepath.Join(homeDir, ".burp-cli")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %v", err)
	}
	
	filePath := filepath.Join(configDir, "scan_history.json")
	
	tracker := &ScanTracker{
		Records: []ScanRecord{},
		filePath: filePath,
	}
	
	// Load existing records if file exists
	if _, err := os.Stat(filePath); err == nil {
		if err := tracker.load(); err != nil {
			return nil, err
		}
	}
	
	return tracker, nil
}

// AddScan adds a new scan record
func (st *ScanTracker) AddScan(scanID, url, configName, scanName string) error {
	record := ScanRecord{
		ScanID:     scanID,
		URL:        url,
		StartTime:  time.Now(),
		Status:     "running",
		ConfigName: configName,
		ScanName:   scanName,
		LastChecked: time.Now(),
	}
	
	st.Records = append(st.Records, record)
	return st.save()
}

// UpdateScanStatus updates the status of a scan
func (st *ScanTracker) UpdateScanStatus(scanID, status string) error {
	for i := range st.Records {
		if st.Records[i].ScanID == scanID {
			st.Records[i].Status = status
			st.Records[i].LastChecked = time.Now()
			return st.save()
		}
	}
	return fmt.Errorf("scan ID %s not found", scanID)
}

// GetAllScans returns all scan records
func (st *ScanTracker) GetAllScans() []ScanRecord {
	return st.Records
}

// GetScanByID returns a specific scan record
func (st *ScanTracker) GetScanByID(scanID string) *ScanRecord {
	for i := range st.Records {
		if st.Records[i].ScanID == scanID {
			return &st.Records[i]
		}
	}
	return nil
}

// RemoveScan removes a scan record
func (st *ScanTracker) RemoveScan(scanID string) error {
	for i := range st.Records {
		if st.Records[i].ScanID == scanID {
			st.Records = append(st.Records[:i], st.Records[i+1:]...)
			return st.save()
		}
	}
	return fmt.Errorf("scan ID %s not found", scanID)
}

// ClearOldScans removes scans older than specified days
func (st *ScanTracker) ClearOldScans(days int) error {
	cutoffDate := time.Now().AddDate(0, 0, -days)
	
	var newRecords []ScanRecord
	for _, record := range st.Records {
		if record.StartTime.After(cutoffDate) {
			newRecords = append(newRecords, record)
		}
	}
	
	st.Records = newRecords
	return st.save()
}

// save writes the scan records to disk
func (st *ScanTracker) save() error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan records: %v", err)
	}
	
	if err := os.WriteFile(st.filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write scan records: %v", err)
	}
	
	return nil
}

// load reads the scan records from disk
func (st *ScanTracker) load() error {
	data, err := os.ReadFile(st.filePath)
	if err != nil {
		return fmt.Errorf("failed to read scan records: %v", err)
	}
	
	if err := json.Unmarshal(data, st); err != nil {
		return fmt.Errorf("failed to unmarshal scan records: %v", err)
	}
	
	return nil
}
