package scheduler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"
)

// StorageData represents the structure of the storage file
type StorageData struct {
	Schedules   []*Schedule `json:"schedules"`
	LastUpdated time.Time   `json:"last_updated"`
	Version     string      `json:"version"`
}

// JSONStorage implements the Storage interface using JSON files
type JSONStorage struct {
	filePath string
	mutex    sync.RWMutex
}

// NewJSONStorage creates a new JSON storage instance
func NewJSONStorage(filePath string) (Storage, error) {
	expandedPath, err := ExpandPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to expand path %s: %v", filePath, err)
	}
	
	storage := &JSONStorage{
		filePath: expandedPath,
	}
	
	if err := storage.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %v", err)
	}
	
	return storage, nil
}

// Initialize sets up the storage system
func (s *JSONStorage) Initialize() error {
	// Ensure the directory exists
	if err := EnsureDirectoryExists(s.filePath); err != nil {
		return fmt.Errorf("failed to create storage directory: %v", err)
	}
	
	// Create the file if it doesn't exist
	if !FileExists(s.filePath) {
		initialData := &StorageData{
			Schedules:   []*Schedule{},
			LastUpdated: time.Now(),
			Version:     "1.0",
		}
		
		if err := s.writeData(initialData); err != nil {
			return fmt.Errorf("failed to create initial storage file: %v", err)
		}
	}
	
	// Validate the existing file
	if _, err := s.readData(); err != nil {
		return fmt.Errorf("failed to validate storage file: %v", err)
	}
	
	return nil
}

// SaveSchedule persists a schedule to storage
func (s *JSONStorage) SaveSchedule(schedule *Schedule) error {
	if err := schedule.Validate(); err != nil {
		return fmt.Errorf("invalid schedule: %v", err)
	}
	
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	data, err := s.readData()
	if err != nil {
		return fmt.Errorf("failed to read storage: %v", err)
	}
	
	// Check if schedule already exists
	for _, existing := range data.Schedules {
		if existing.ID == schedule.ID {
			return fmt.Errorf("schedule with ID %s already exists", schedule.ID)
		}
		// Also check for duplicate names
		if existing.Name == schedule.Name {
			return fmt.Errorf("schedule with name '%s' already exists", schedule.Name)
		}
	}
	
	// Add the new schedule
	data.Schedules = append(data.Schedules, schedule)
	data.LastUpdated = time.Now()
	
	return s.writeData(data)
}

// LoadSchedules loads all schedules from storage
func (s *JSONStorage) LoadSchedules() ([]*Schedule, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	data, err := s.readData()
	if err != nil {
		return nil, fmt.Errorf("failed to read storage: %v", err)
	}
	
	// Return a copy to prevent external modifications
	schedules := make([]*Schedule, len(data.Schedules))
	copy(schedules, data.Schedules)
	
	return schedules, nil
}

// DeleteSchedule removes a schedule from storage
func (s *JSONStorage) DeleteSchedule(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	data, err := s.readData()
	if err != nil {
		return fmt.Errorf("failed to read storage: %v", err)
	}
	
	// Find and remove the schedule
	found := false
	for idx, schedule := range data.Schedules {
		if schedule.ID == id {
			// Remove the schedule from the slice
			data.Schedules = append(data.Schedules[:idx], data.Schedules[idx+1:]...)
			found = true
			break
		}
	}
	
	if !found {
		return fmt.Errorf("schedule with ID %s not found", id)
	}
	
	data.LastUpdated = time.Now()
	return s.writeData(data)
}

// UpdateSchedule updates an existing schedule in storage
func (s *JSONStorage) UpdateSchedule(schedule *Schedule) error {
	if err := schedule.Validate(); err != nil {
		return fmt.Errorf("invalid schedule: %v", err)
	}
	
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	data, err := s.readData()
	if err != nil {
		return fmt.Errorf("failed to read storage: %v", err)
	}
	
	// Find and update the schedule
	found := false
	for idx, existing := range data.Schedules {
		if existing.ID == schedule.ID {
			// Check for name conflicts with other schedules
			for j, other := range data.Schedules {
				if idx != j && other.Name == schedule.Name {
					return fmt.Errorf("schedule with name '%s' already exists", schedule.Name)
				}
			}
			
			data.Schedules[idx] = schedule
			found = true
			break
		}
	}
	
	if !found {
		return fmt.Errorf("schedule with ID %s not found", schedule.ID)
	}
	
	data.LastUpdated = time.Now()
	return s.writeData(data)
}

// ScheduleExists checks if a schedule with the given ID exists
func (s *JSONStorage) ScheduleExists(id string) (bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	data, err := s.readData()
	if err != nil {
		return false, fmt.Errorf("failed to read storage: %v", err)
	}
	
	for _, schedule := range data.Schedules {
		if schedule.ID == id {
			return true, nil
		}
	}
	
	return false, nil
}

// GetScheduleByID retrieves a schedule by its ID
func (s *JSONStorage) GetScheduleByID(id string) (*Schedule, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	data, err := s.readData()
	if err != nil {
		return nil, fmt.Errorf("failed to read storage: %v", err)
	}
	
	for _, schedule := range data.Schedules {
		if schedule.ID == id {
			// Return a copy to prevent external modifications
			scheduleCopy := *schedule
			return &scheduleCopy, nil
		}
	}
	
	return nil, fmt.Errorf("schedule with ID %s not found", id)
}

// GetScheduleByName retrieves a schedule by its name
func (s *JSONStorage) GetScheduleByName(name string) (*Schedule, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	data, err := s.readData()
	if err != nil {
		return nil, fmt.Errorf("failed to read storage: %v", err)
	}
	
	for _, schedule := range data.Schedules {
		if schedule.Name == name {
			// Return a copy to prevent external modifications
			scheduleCopy := *schedule
			return &scheduleCopy, nil
		}
	}
	
	return nil, fmt.Errorf("schedule with name '%s' not found", name)
}

// readData reads and parses the storage file
func (s *JSONStorage) readData() (*StorageData, error) {
	if !FileExists(s.filePath) {
		return &StorageData{
			Schedules:   []*Schedule{},
			LastUpdated: time.Now(),
			Version:     "1.0",
		}, nil
	}
	
	data, err := ioutil.ReadFile(s.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}
	
	var storageData StorageData
	if err := json.Unmarshal(data, &storageData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	
	// Validate all schedules
	for _, schedule := range storageData.Schedules {
		if err := schedule.Validate(); err != nil {
			return nil, fmt.Errorf("invalid schedule %s: %v", schedule.ID, err)
		}
	}
	
	return &storageData, nil
}

// writeData writes the storage data to file atomically
func (s *JSONStorage) writeData(data *StorageData) error {
	// Marshal to JSON with indentation for readability
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	
	// Write to a temporary file first for atomic operation
	tempFile := s.filePath + ".tmp"
	if err := ioutil.WriteFile(tempFile, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write temporary file: %v", err)
	}
	
	// Atomically replace the original file
	if err := os.Rename(tempFile, s.filePath); err != nil {
		// Clean up the temporary file if rename fails
		os.Remove(tempFile)
		return fmt.Errorf("failed to replace storage file: %v", err)
	}
	
	return nil
}

// Backup creates a backup of the storage file
func (s *JSONStorage) Backup() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	if !FileExists(s.filePath) {
		return fmt.Errorf("storage file does not exist")
	}
	
	// Create backup filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	backupPath := s.filePath + ".backup." + timestamp
	
	// Copy the file
	data, err := ioutil.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read storage file: %v", err)
	}
	
	if err := ioutil.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %v", err)
	}
	
	return nil
}

// Restore restores from a backup file
func (s *JSONStorage) Restore(backupPath string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if !FileExists(backupPath) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}
	
	// Validate the backup file first
	data, err := ioutil.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %v", err)
	}
	
	var storageData StorageData
	if err := json.Unmarshal(data, &storageData); err != nil {
		return fmt.Errorf("backup file is not valid JSON: %v", err)
	}
	
	// Validate all schedules in the backup
	for _, schedule := range storageData.Schedules {
		if err := schedule.Validate(); err != nil {
			return fmt.Errorf("backup contains invalid schedule %s: %v", schedule.ID, err)
		}
	}
	
	// Copy the backup to the main storage file
	if err := ioutil.WriteFile(s.filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to restore from backup: %v", err)
	}
	
	return nil
}

// GetStorageInfo returns information about the storage
func (s *JSONStorage) GetStorageInfo() (map[string]interface{}, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	info := make(map[string]interface{})
	info["file_path"] = s.filePath
	info["file_exists"] = FileExists(s.filePath)
	
	if FileExists(s.filePath) {
		stat, err := os.Stat(s.filePath)
		if err == nil {
			info["file_size"] = stat.Size()
			info["modified_time"] = stat.ModTime()
		}
		
		data, err := s.readData()
		if err == nil {
			info["schedule_count"] = len(data.Schedules)
			info["last_updated"] = data.LastUpdated
			info["version"] = data.Version
		}
	}
	
	return info, nil
}