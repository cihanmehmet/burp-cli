package scheduler

import "time"

// Scheduler defines the main scheduler interface
type Scheduler interface {
	// Start begins the scheduler daemon
	Start() error
	
	// Stop gracefully shuts down the scheduler daemon
	Stop() error
	
	// AddSchedule adds a new schedule to the system
	AddSchedule(schedule *Schedule) error
	
	// RemoveSchedule removes a schedule by ID
	RemoveSchedule(id string) error
	
	// ListSchedules returns all active schedules
	ListSchedules() ([]*Schedule, error)
	
	// GetScheduleStatus returns the status of a specific schedule
	GetScheduleStatus(id string) (*ScheduleStatus, error)
	
	// IsRunning returns true if the scheduler daemon is running
	IsRunning() bool
	
	// UpdateSchedule updates an existing schedule
	UpdateSchedule(schedule *Schedule) error
}

// Storage defines the interface for persistent schedule storage
type Storage interface {
	// SaveSchedule persists a schedule to storage
	SaveSchedule(schedule *Schedule) error
	
	// LoadSchedules loads all schedules from storage
	LoadSchedules() ([]*Schedule, error)
	
	// DeleteSchedule removes a schedule from storage
	DeleteSchedule(id string) error
	
	// UpdateSchedule updates an existing schedule in storage
	UpdateSchedule(schedule *Schedule) error
	
	// ScheduleExists checks if a schedule with the given ID exists
	ScheduleExists(id string) (bool, error)
	
	// Initialize sets up the storage system
	Initialize() error
	
	// GetScheduleByID retrieves a schedule by its ID
	GetScheduleByID(id string) (*Schedule, error)
	
	// GetScheduleByName retrieves a schedule by its name
	GetScheduleByName(name string) (*Schedule, error)
}

// Executor defines the interface for executing scheduled scans
type Executor interface {
	// ExecuteSchedule executes a scheduled scan
	ExecuteSchedule(schedule *Schedule) error
	
	// ValidateSchedule validates that a schedule can be executed
	ValidateSchedule(schedule *Schedule) error
	
	// GetExecutionHistory returns execution history for a schedule
	GetExecutionHistory(scheduleID string) ([]*ExecutionRecord, error)
}

// CronCalculator defines the interface for time calculations
type CronCalculator interface {
	// CalculateNextRun calculates the next execution time for a schedule
	CalculateNextRun(schedule *Schedule, from time.Time) (time.Time, error)
	
	// IsTimeToRun checks if it's time to execute a schedule
	IsTimeToRun(schedule *Schedule, now time.Time) bool
	
	// GetTimeUntilNext returns the duration until the next execution
	GetTimeUntilNext(schedule *Schedule, now time.Time) (time.Duration, error)
}

// Logger defines the interface for scheduler logging
type Logger interface {
	// Debug logs debug-level messages
	Debug(format string, args ...interface{})
	
	// Info logs info-level messages
	Info(format string, args ...interface{})
	
	// Warn logs warning-level messages
	Warn(format string, args ...interface{})
	
	// Error logs error-level messages
	Error(format string, args ...interface{})
	
	// LogExecution logs a schedule execution
	LogExecution(schedule *Schedule, success bool, duration time.Duration, err error)
}

// ExecutionRecord represents a record of a schedule execution
type ExecutionRecord struct {
	ScheduleID  string    `json:"schedule_id"`
	ExecutedAt  time.Time `json:"executed_at"`
	Success     bool      `json:"success"`
	Duration    time.Duration `json:"duration"`
	Error       string    `json:"error,omitempty"`
	ScanID      string    `json:"scan_id,omitempty"`
	ResultsPath string    `json:"results_path,omitempty"`
}

// SchedulerConfig holds configuration for the scheduler
type SchedulerConfig struct {
	// StoragePath is the path to the schedule storage file
	StoragePath string
	
	// LogPath is the path to the scheduler log file
	LogPath string
	
	// PIDPath is the path to the daemon PID file
	PIDPath string
	
	// CheckInterval is how often to check for schedules to run
	CheckInterval time.Duration
	
	// MaxConcurrentScans is the maximum number of scans to run simultaneously
	MaxConcurrentScans int
	
	// RetryAttempts is the number of times to retry failed scans
	RetryAttempts int
	
	// RetryInterval is the time to wait between retry attempts
	RetryInterval time.Duration
}

// DefaultSchedulerConfig returns a default scheduler configuration
func DefaultSchedulerConfig() *SchedulerConfig {
	return &SchedulerConfig{
		StoragePath:        "~/.burp-cli/schedules.json",
		LogPath:           "~/.burp-cli/scheduler.log", 
		PIDPath:           "~/.burp-cli/scheduler.pid",
		CheckInterval:     time.Minute,
		MaxConcurrentScans: 3,
		RetryAttempts:     3,
		RetryInterval:     time.Minute * 5,
	}
}