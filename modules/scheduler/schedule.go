package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule represents a scheduled scan configuration
type Schedule struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Type       string     `json:"type"`        // "daily", "weekly", "monthly"
	Pattern    Pattern    `json:"pattern"`
	ScanConfig ScanConfig `json:"scan_config"`
	CreatedAt  time.Time  `json:"created_at"`
	LastRun    *time.Time `json:"last_run,omitempty"`
	NextRun    time.Time  `json:"next_run"`
	Enabled    bool       `json:"enabled"`
}

// Pattern defines when a schedule should run
type Pattern struct {
	Time       string   `json:"time"`                     // "HH:MM" format (24-hour)
	Days       []string `json:"days,omitempty"`           // For weekly: ["Monday", "Friday"]
	DayOfMonth int      `json:"day_of_month,omitempty"`   // For monthly: 1-31 or -1 for last day
}

// ScanConfig contains all parameters needed to execute a scan
type ScanConfig struct {
	ScanType   string            `json:"scan_type"`   // "url", "url_list", "nmap"
	Target     string            `json:"target"`      // URL, file path, etc.
	Parameters map[string]string `json:"parameters"`  // All burp-cli parameters
}

// ScheduleStatus represents the current status of a schedule
type ScheduleStatus struct {
	Schedule    *Schedule `json:"schedule"`
	IsRunning   bool      `json:"is_running"`
	LastError   string    `json:"last_error,omitempty"`
	NextRunIn   string    `json:"next_run_in"`
	ExecutionCount int    `json:"execution_count"`
}

// Validate checks if the schedule configuration is valid
func (s *Schedule) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("schedule ID cannot be empty")
	}
	
	if s.Name == "" {
		return fmt.Errorf("schedule name cannot be empty")
	}
	
	if s.Type != "daily" && s.Type != "weekly" && s.Type != "monthly" {
		return fmt.Errorf("schedule type must be 'daily', 'weekly', or 'monthly'")
	}
	
	if err := s.Pattern.Validate(s.Type); err != nil {
		return fmt.Errorf("invalid pattern: %v", err)
	}
	
	if err := s.ScanConfig.Validate(); err != nil {
		return fmt.Errorf("invalid scan config: %v", err)
	}
	
	return nil
}

// Validate checks if the pattern is valid for the given schedule type
func (p *Pattern) Validate(scheduleType string) error {
	// Validate time format
	if err := validateTimeFormat(p.Time); err != nil {
		return err
	}
	
	switch scheduleType {
	case "daily":
		// Daily schedules don't need days or day_of_month
		if len(p.Days) > 0 {
			return fmt.Errorf("daily schedules should not specify days")
		}
		if p.DayOfMonth != 0 {
			return fmt.Errorf("daily schedules should not specify day_of_month")
		}
		
	case "weekly":
		// Weekly schedules need at least one day
		if len(p.Days) == 0 {
			return fmt.Errorf("weekly schedules must specify at least one day")
		}
		if p.DayOfMonth != 0 {
			return fmt.Errorf("weekly schedules should not specify day_of_month")
		}
		// Validate day names
		for _, day := range p.Days {
			if !isValidDayName(day) {
				return fmt.Errorf("invalid day name: %s", day)
			}
		}
		
	case "monthly":
		// Monthly schedules need day_of_month
		if p.DayOfMonth == 0 {
			return fmt.Errorf("monthly schedules must specify day_of_month")
		}
		if len(p.Days) > 0 {
			return fmt.Errorf("monthly schedules should not specify days")
		}
		// Validate day of month (-1 for last day, or 1-31)
		if p.DayOfMonth < -1 || p.DayOfMonth > 31 || p.DayOfMonth == 0 {
			return fmt.Errorf("day_of_month must be -1 (last day) or 1-31")
		}
	}
	
	return nil
}

// Validate checks if the scan configuration is valid
func (sc *ScanConfig) Validate() error {
	if sc.ScanType == "" {
		return fmt.Errorf("scan_type cannot be empty")
	}
	
	if sc.ScanType != "url" && sc.ScanType != "url_list" && sc.ScanType != "nmap" {
		return fmt.Errorf("scan_type must be 'url', 'url_list', or 'nmap'")
	}
	
	if sc.Target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	
	// Additional validation based on scan type
	switch sc.ScanType {
	case "url":
		// For URL scans, target should be a valid URL
		if !strings.HasPrefix(sc.Target, "http://") && !strings.HasPrefix(sc.Target, "https://") {
			return fmt.Errorf("URL target must start with http:// or https://")
		}
	case "url_list":
		// For URL list scans, target should be a file path
		// We'll validate file existence during execution
	case "nmap":
		// For Nmap scans, target should be an XML file path
		if !strings.HasSuffix(strings.ToLower(sc.Target), ".xml") {
			return fmt.Errorf("Nmap target must be an XML file")
		}
	}
	
	return nil
}

// validateTimeFormat validates HH:MM format (24-hour)
func validateTimeFormat(timeStr string) error {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return fmt.Errorf("time must be in HH:MM format")
	}
	
	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid hour: %s", parts[0])
	}
	if hour < 0 || hour > 23 {
		return fmt.Errorf("hour must be between 00 and 23")
	}
	
	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid minute: %s", parts[1])
	}
	if minute < 0 || minute > 59 {
		return fmt.Errorf("minute must be between 00 and 59")
	}
	
	return nil
}

// isValidDayName checks if the day name is valid
func isValidDayName(day string) bool {
	day = strings.ToLower(day)
	validDays := []string{
		"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
		"mon", "tue", "wed", "thu", "fri", "sat", "sun",
	}
	
	for _, validDay := range validDays {
		if day == validDay {
			return true
		}
	}
	return false
}

// normalizeDayName converts day names to full lowercase format
func normalizeDayName(day string) string {
	day = strings.ToLower(day)
	dayMap := map[string]string{
		"mon": "monday",
		"tue": "tuesday", 
		"wed": "wednesday",
		"thu": "thursday",
		"fri": "friday",
		"sat": "saturday",
		"sun": "sunday",
	}
	
	if fullDay, exists := dayMap[day]; exists {
		return fullDay
	}
	return day
}

// GetNormalizedDays returns normalized day names
func (p *Pattern) GetNormalizedDays() []string {
	normalized := make([]string, len(p.Days))
	for i, day := range p.Days {
		normalized[i] = normalizeDayName(day)
	}
	return normalized
}

// String returns a human-readable representation of the schedule
func (s *Schedule) String() string {
	var pattern string
	switch s.Type {
	case "daily":
		pattern = fmt.Sprintf("Daily at %s", s.Pattern.Time)
	case "weekly":
		days := strings.Join(s.Pattern.Days, ", ")
		pattern = fmt.Sprintf("Weekly on %s at %s", days, s.Pattern.Time)
	case "monthly":
		if s.Pattern.DayOfMonth == -1 {
			pattern = fmt.Sprintf("Monthly on last day at %s", s.Pattern.Time)
		} else {
			pattern = fmt.Sprintf("Monthly on day %d at %s", s.Pattern.DayOfMonth, s.Pattern.Time)
		}
	}
	
	return fmt.Sprintf("%s (%s): %s -> %s", s.Name, s.ID, pattern, s.ScanConfig.Target)
}