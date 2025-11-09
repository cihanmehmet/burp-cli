package scheduler

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateScheduleID generates a unique ID for a schedule
func GenerateScheduleID() string {
	// Generate a random 8-character ID
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return fmt.Sprintf("sched_%x", bytes)
}

// ExpandPath expands ~ to the user's home directory
func ExpandPath(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %v", err)
	}
	
	return filepath.Join(homeDir, path[1:]), nil
}

// EnsureDirectoryExists creates a directory if it doesn't exist
func EnsureDirectoryExists(path string) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0755)
	}
	return nil
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

// ParseTimeString parses a time string in HH:MM format
func ParseTimeString(timeStr string) (hour, minute int, err error) {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid time format, expected HH:MM")
	}
	
	var h, m int
	if _, err := fmt.Sscanf(parts[0], "%d", &h); err != nil {
		return 0, 0, fmt.Errorf("invalid hour: %s", parts[0])
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &m); err != nil {
		return 0, 0, fmt.Errorf("invalid minute: %s", parts[1])
	}
	
	if h < 0 || h > 23 {
		return 0, 0, fmt.Errorf("hour must be between 0 and 23")
	}
	if m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("minute must be between 0 and 59")
	}
	
	return h, m, nil
}

// GetWeekdayFromString converts a day name to time.Weekday
func GetWeekdayFromString(day string) (time.Weekday, error) {
	day = strings.ToLower(day)
	
	dayMap := map[string]time.Weekday{
		"sunday":    time.Sunday,
		"monday":    time.Monday,
		"tuesday":   time.Tuesday,
		"wednesday": time.Wednesday,
		"thursday":  time.Thursday,
		"friday":    time.Friday,
		"saturday":  time.Saturday,
		"sun":       time.Sunday,
		"mon":       time.Monday,
		"tue":       time.Tuesday,
		"wed":       time.Wednesday,
		"thu":       time.Thursday,
		"fri":       time.Friday,
		"sat":       time.Saturday,
	}
	
	if weekday, exists := dayMap[day]; exists {
		return weekday, nil
	}
	
	return time.Sunday, fmt.Errorf("invalid day name: %s", day)
}

// IsValidScheduleType checks if a schedule type is valid
func IsValidScheduleType(scheduleType string) bool {
	validTypes := []string{"daily", "weekly", "monthly"}
	for _, validType := range validTypes {
		if scheduleType == validType {
			return true
		}
	}
	return false
}

// IsValidScanType checks if a scan type is valid
func IsValidScanType(scanType string) bool {
	validTypes := []string{"url", "url_list", "nmap"}
	for _, validType := range validTypes {
		if scanType == validType {
			return true
		}
	}
	return false
}

// SanitizeScheduleName sanitizes a schedule name for safe storage
func SanitizeScheduleName(name string) string {
	// Remove or replace problematic characters
	name = strings.TrimSpace(name)
	if name == "" {
		return "Unnamed Schedule"
	}
	
	// Limit length
	if len(name) > 100 {
		name = name[:100]
	}
	
	return name
}

// GetConfigDirectory returns the burp-cli configuration directory
func GetConfigDirectory() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %v", err)
	}
	
	configDir := filepath.Join(homeDir, ".burp-cli")
	
	// Ensure the directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}
	
	return configDir, nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// IsProcessRunning checks if a process with the given PID is running
func IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	
	// On Unix systems, we can send signal 0 to check if process exists
	err = process.Signal(os.Signal(nil))
	return err == nil
}

// GetCurrentTime returns the current time (useful for testing)
func GetCurrentTime() time.Time {
	return time.Now()
}

// TimeUntilNext calculates the time until the next occurrence of the given time
func TimeUntilNext(targetHour, targetMinute int, from time.Time) time.Duration {
	now := from
	target := time.Date(now.Year(), now.Month(), now.Day(), targetHour, targetMinute, 0, 0, now.Location())
	
	// If the target time has already passed today, schedule for tomorrow
	if target.Before(now) || target.Equal(now) {
		target = target.Add(24 * time.Hour)
	}
	
	return target.Sub(now)
}