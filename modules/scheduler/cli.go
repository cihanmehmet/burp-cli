package scheduler

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joanbono/color"
)

// Defining colors
var yellow = color.New(color.Bold, color.FgYellow).SprintfFunc()
var red = color.New(color.Bold, color.FgRed).SprintfFunc()
var cyan = color.New(color.Bold, color.FgCyan).SprintfFunc()
var green = color.New(color.Bold, color.FgGreen).SprintfFunc()
var cyanBG = color.New(color.Bold, color.BgCyan, color.FgBlack).SprintfFunc()
var yellowBG = color.New(color.Bold, color.BgYellow, color.FgBlack).SprintfFunc()
var greenBG = color.New(color.Bold, color.BgGreen, color.FgBlack).SprintfFunc()

// ScheduleCommand represents a schedule command
type ScheduleCommand struct {
	storage Storage
}

// NewScheduleCLI creates a new schedule command handler (alias for compatibility)
func NewScheduleCLI() (*ScheduleCommand, error) {
	return NewScheduleCommand()
}

// NewScheduleCommand creates a new schedule command handler
func NewScheduleCommand() (*ScheduleCommand, error) {
	configDir, err := GetConfigDirectory()
	if err != nil {
		return nil, fmt.Errorf("failed to get config directory: %v", err)
	}
	
	storagePath := filepath.Join(configDir, "schedules.json")
	storage, err := NewJSONStorage(storagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %v", err)
	}
	
	return &ScheduleCommand{
		storage: storage,
	}, nil
}

// HandleScheduleCommand handles the main schedule command dispatch
func (sc *ScheduleCommand) HandleScheduleCommand(args []string) error {
	if len(args) == 0 {
		return sc.ShowHelp()
	}
	
	subcommand := args[0]
	subArgs := args[1:]
	
	switch subcommand {
	case "create":
		return sc.HandleCreateCommand(subArgs)
	case "list":
		return sc.HandleListCommand(subArgs)
	case "delete", "remove":
		return sc.HandleDeleteCommand(subArgs)
	case "status":
		return sc.HandleStatusCommand(subArgs)
	case "test":
		return sc.HandleTestCommand(subArgs)
	case "daemon":
		return sc.HandleDaemonCommand(subArgs)
	case "help", "-h", "--help":
		return sc.ShowHelp()
	default:
		fmt.Fprintf(color.Output, "%v Unknown schedule command: %s\n", red(" [-] ERROR:"), subcommand)
		return sc.ShowHelp()
	}
}

// HandleCreateCommand handles schedule creation
func (sc *ScheduleCommand) HandleCreateCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(color.Output, "%v Schedule type required (daily, weekly, monthly)\n", red(" [-] ERROR:"))
		return sc.ShowCreateHelp()
	}
	
	scheduleType := args[0]
	if !IsValidScheduleType(scheduleType) {
		fmt.Fprintf(color.Output, "%v Invalid schedule type: %s\n", red(" [-] ERROR:"), scheduleType)
		return sc.ShowCreateHelp()
	}
	
	// Parse command line arguments for schedule creation
	config, err := sc.parseCreateArgs(scheduleType, args[1:])
	if err != nil {
		fmt.Fprintf(color.Output, "%v %v\n", red(" [-] ERROR:"), err)
		return sc.ShowCreateHelp()
	}
	
	// Create the schedule
	schedule := &Schedule{
		ID:         GenerateScheduleID(),
		Name:       config.Name,
		Type:       scheduleType,
		Pattern:    config.Pattern,
		ScanConfig: config.ScanConfig,
		CreatedAt:  time.Now(),
		Enabled:    true,
	}
	
	// Calculate next run time
	calc := NewCronCalculator()
	nextRun, err := calc.CalculateNextRun(schedule, time.Now())
	if err != nil {
		return fmt.Errorf("failed to calculate next run time: %v", err)
	}
	schedule.NextRun = nextRun
	
	// Save the schedule
	if err := sc.storage.SaveSchedule(schedule); err != nil {
		return fmt.Errorf("failed to save schedule: %v", err)
	}
	
	fmt.Fprintf(color.Output, "%v Schedule created successfully!\n", green(" [+] SUCCESS:"))
	fmt.Fprintf(color.Output, "  • ID: %s\n", schedule.ID)
	fmt.Fprintf(color.Output, "  • Name: %s\n", schedule.Name)
	fmt.Fprintf(color.Output, "  • Type: %s\n", schedule.Type)
	fmt.Fprintf(color.Output, "  • Next run: %s\n", schedule.NextRun.Format("2006-01-02 15:04:05 MST"))
	
	return nil
}

// HandleListCommand handles listing schedules
func (sc *ScheduleCommand) HandleListCommand(args []string) error {
	schedules, err := sc.storage.LoadSchedules()
	if err != nil {
		return fmt.Errorf("failed to load schedules: %v", err)
	}
	
	if len(schedules) == 0 {
		fmt.Fprintf(color.Output, "%v No schedules found\n", cyan(" [i] INFO:"))
		fmt.Fprintf(color.Output, "  Use 'burp-cli schedule create' to create a new schedule\n")
		return nil
	}
	
	fmt.Fprintf(color.Output, "%v Active Schedules:\n", cyan(" [i] INFO:"))
	fmt.Fprintf(color.Output, "\n")
	
	for i, schedule := range schedules {
		status := "Enabled"
		if !schedule.Enabled {
			status = "Disabled"
		}
		
		fmt.Fprintf(color.Output, "%v %s\n", yellowBG(fmt.Sprintf(" [%d] %s ", i+1, schedule.ID)), schedule.Name)
		fmt.Fprintf(color.Output, "  • Type: %s\n", schedule.Type)
		fmt.Fprintf(color.Output, "  • Pattern: %s\n", sc.formatPattern(schedule))
		fmt.Fprintf(color.Output, "  • Target: %s\n", schedule.ScanConfig.Target)
		fmt.Fprintf(color.Output, "  • Status: %s\n", status)
		fmt.Fprintf(color.Output, "  • Next run: %s\n", schedule.NextRun.Format("2006-01-02 15:04:05 MST"))
		
		if schedule.LastRun != nil {
			fmt.Fprintf(color.Output, "  • Last run: %s\n", schedule.LastRun.Format("2006-01-02 15:04:05 MST"))
		}
		
		fmt.Fprintf(color.Output, "\n")
	}
	
	return nil
}

// HandleDeleteCommand handles schedule deletion
func (sc *ScheduleCommand) HandleDeleteCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(color.Output, "%v Schedule ID required\n", red(" [-] ERROR:"))
		fmt.Fprintf(color.Output, "  Use 'burp-cli schedule list' to see available schedules\n")
		return nil
	}
	
	scheduleID := args[0]
	
	// Check if schedule exists
	exists, err := sc.storage.ScheduleExists(scheduleID)
	if err != nil {
		return fmt.Errorf("failed to check schedule existence: %v", err)
	}
	
	if !exists {
		fmt.Fprintf(color.Output, "%v Schedule with ID '%s' not found\n", red(" [-] ERROR:"), scheduleID)
		return nil
	}
	
	// Get schedule details for confirmation
	schedule, err := sc.storage.GetScheduleByID(scheduleID)
	if err != nil {
		return fmt.Errorf("failed to get schedule details: %v", err)
	}
	
	// Show confirmation
	fmt.Fprintf(color.Output, "%v Are you sure you want to delete this schedule?\n", yellow(" [!] WARNING:"))
	fmt.Fprintf(color.Output, "  • ID: %s\n", schedule.ID)
	fmt.Fprintf(color.Output, "  • Name: %s\n", schedule.Name)
	fmt.Fprintf(color.Output, "  • Type: %s\n", schedule.Type)
	fmt.Fprintf(color.Output, "  • Target: %s\n", schedule.ScanConfig.Target)
	fmt.Fprintf(color.Output, "\nType 'yes' to confirm deletion: ")
	
	var confirmation string
	fmt.Scanln(&confirmation)
	
	if strings.ToLower(confirmation) != "yes" {
		fmt.Fprintf(color.Output, "%v Deletion cancelled\n", cyan(" [i] INFO:"))
		return nil
	}
	
	// Delete the schedule
	if err := sc.storage.DeleteSchedule(scheduleID); err != nil {
		return fmt.Errorf("failed to delete schedule: %v", err)
	}
	
	fmt.Fprintf(color.Output, "%v Schedule deleted successfully\n", green(" [+] SUCCESS:"))
	return nil
}

// HandleStatusCommand handles schedule status display
func (sc *ScheduleCommand) HandleStatusCommand(args []string) error {
	schedules, err := sc.storage.LoadSchedules()
	if err != nil {
		return fmt.Errorf("failed to load schedules: %v", err)
	}
	
	if len(schedules) == 0 {
		fmt.Fprintf(color.Output, "%v No schedules found\n", cyan(" [i] INFO:"))
		return nil
	}
	
	fmt.Fprintf(color.Output, "%v Schedule Status:\n", cyan(" [i] INFO:"))
	fmt.Fprintf(color.Output, "\n")
	
	calc := NewCronCalculator()
	now := time.Now()
	
	for _, schedule := range schedules {
		timeUntil, err := calc.GetTimeUntilNext(schedule, now)
		if err != nil {
			timeUntil = 0
		}
		
		fmt.Fprintf(color.Output, "%v %s\n", greenBG(fmt.Sprintf(" %s ", schedule.ID)), schedule.Name)
		fmt.Fprintf(color.Output, "  • Next run: %s\n", schedule.NextRun.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(color.Output, "  • Time until next run: %s\n", FormatDuration(timeUntil))
		
		if schedule.LastRun != nil {
			fmt.Fprintf(color.Output, "  • Last run: %s\n", schedule.LastRun.Format("2006-01-02 15:04:05 MST"))
		} else {
			fmt.Fprintf(color.Output, "  • Last run: Never\n")
		}
		
		status := "Enabled"
		if !schedule.Enabled {
			status = "Disabled"
		}
		fmt.Fprintf(color.Output, "  • Status: %s\n", status)
		fmt.Fprintf(color.Output, "\n")
	}
	
	return nil
}

// ShowHelp displays general help for schedule commands
func (sc *ScheduleCommand) ShowHelp() error {
	fmt.Fprintf(color.Output, "%v burp-cli Schedule Commands:\n", cyan(" [i] INFO:"))
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Available Commands:\n", greenBG(" [*] COMMANDS:"))
	fmt.Fprintf(color.Output, "  • burp-cli schedule create <type> [options]  - Create a new schedule\n")
	fmt.Fprintf(color.Output, "  • burp-cli schedule list                     - List all schedules\n")
	fmt.Fprintf(color.Output, "  • burp-cli schedule status                   - Show schedule status\n")
	fmt.Fprintf(color.Output, "  • burp-cli schedule delete <id>              - Delete a schedule\n")
	fmt.Fprintf(color.Output, "  • burp-cli schedule test <id>                - Test a schedule (dry-run)\n")
	fmt.Fprintf(color.Output, "  • burp-cli schedule daemon [--foreground]    - Run scheduler daemon\n")
	fmt.Fprintf(color.Output, "  • burp-cli schedule help                     - Show this help\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Schedule Types:\n", greenBG(" [*] TYPES:"))
	fmt.Fprintf(color.Output, "  • daily   - Run every day at specified time\n")
	fmt.Fprintf(color.Output, "  • weekly  - Run on specific days of the week\n")
	fmt.Fprintf(color.Output, "  • monthly - Run on specific day of the month\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Examples:\n", greenBG(" [*] EXAMPLES:"))
	fmt.Fprintf(color.Output, "  # Create daily schedule\n")
	fmt.Fprintf(color.Output, "  burp-cli schedule create daily --time 21:00 --name \"Daily Scan\" --url https://example.com --config 1\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "  # Create weekly schedule\n")
	fmt.Fprintf(color.Output, "  burp-cli schedule create weekly --time 09:00 --days mon,fri --name \"Weekly Scan\" --url-list urls.txt\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "  # Create monthly schedule\n")
	fmt.Fprintf(color.Output, "  burp-cli schedule create monthly --time 02:00 --day 1 --name \"Monthly Scan\" --nmap scan.xml\n")
	
	return nil
}

// ShowCreateHelp displays help for schedule creation
func (sc *ScheduleCommand) ShowCreateHelp() error {
	fmt.Fprintf(color.Output, "%v Schedule Creation Help:\n", cyan(" [i] INFO:"))
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Required Parameters:\n", greenBG(" [*] REQUIRED:"))
	fmt.Fprintf(color.Output, "  --time HH:MM        Time to run (24-hour format)\n")
	fmt.Fprintf(color.Output, "  --name \"Name\"       Schedule name\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Scan Target (choose one):\n", greenBG(" [*] TARGET:"))
	fmt.Fprintf(color.Output, "  --url URL           Single URL to scan\n")
	fmt.Fprintf(color.Output, "  --url-list FILE     File containing URLs\n")
	fmt.Fprintf(color.Output, "  --nmap FILE         Nmap XML file\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Schedule-Specific Parameters:\n", greenBG(" [*] SCHEDULE:"))
	fmt.Fprintf(color.Output, "  Daily:   (no additional parameters)\n")
	fmt.Fprintf(color.Output, "  Weekly:  --days mon,tue,wed,thu,fri,sat,sun\n")
	fmt.Fprintf(color.Output, "  Monthly: --day N (1-31) or --day last\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Optional Scan Parameters:\n", greenBG(" [*] OPTIONAL:"))
	fmt.Fprintf(color.Output, "  --config N          Burp configuration number\n")
	fmt.Fprintf(color.Output, "  --burp-config NAME  Burp configuration name\n")
	fmt.Fprintf(color.Output, "  --auto-export       Enable auto-export\n")
	fmt.Fprintf(color.Output, "  --export-dir DIR    Export directory\n")
	fmt.Fprintf(color.Output, "  --scan-name NAME    Custom scan name\n")
	
	return nil
}

// parseCreateArgs parses command line arguments for schedule creation
func (sc *ScheduleCommand) parseCreateArgs(scheduleType string, args []string) (*CreateConfig, error) {
	config := &CreateConfig{
		Pattern:    Pattern{},
		ScanConfig: ScanConfig{},
	}
	
	// Parse arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		
		switch arg {
		case "--time":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--time requires a value")
			}
			config.Pattern.Time = args[i+1]
			i++
			
		case "--name":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--name requires a value")
			}
			config.Name = args[i+1]
			i++
			
		case "--days":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--days requires a value")
			}
			config.Pattern.Days = strings.Split(args[i+1], ",")
			i++
			
		case "--day":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--day requires a value")
			}
			if args[i+1] == "last" {
				config.Pattern.DayOfMonth = -1
			} else {
				day, err := strconv.Atoi(args[i+1])
				if err != nil {
					return nil, fmt.Errorf("invalid day number: %s", args[i+1])
				}
				config.Pattern.DayOfMonth = day
			}
			i++
			
		case "--url":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--url requires a value")
			}
			config.ScanConfig.ScanType = "url"
			config.ScanConfig.Target = args[i+1]
			i++
			
		case "--url-list":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--url-list requires a value")
			}
			config.ScanConfig.ScanType = "url_list"
			config.ScanConfig.Target = args[i+1]
			i++
			
		case "--nmap":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--nmap requires a value")
			}
			config.ScanConfig.ScanType = "nmap"
			config.ScanConfig.Target = args[i+1]
			i++
			
		case "--config":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--config requires a value")
			}
			if config.ScanConfig.Parameters == nil {
				config.ScanConfig.Parameters = make(map[string]string)
			}
			config.ScanConfig.Parameters["config_number"] = args[i+1]
			i++
			
		case "--burp-config":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--burp-config requires a value")
			}
			if config.ScanConfig.Parameters == nil {
				config.ScanConfig.Parameters = make(map[string]string)
			}
			config.ScanConfig.Parameters["burp_config"] = args[i+1]
			i++
			
		case "--auto-export":
			if config.ScanConfig.Parameters == nil {
				config.ScanConfig.Parameters = make(map[string]string)
			}
			config.ScanConfig.Parameters["auto_export"] = "true"
			
		case "--export-dir":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--export-dir requires a value")
			}
			if config.ScanConfig.Parameters == nil {
				config.ScanConfig.Parameters = make(map[string]string)
			}
			config.ScanConfig.Parameters["export_dir"] = args[i+1]
			i++
			
		case "--scan-name":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--scan-name requires a value")
			}
			if config.ScanConfig.Parameters == nil {
				config.ScanConfig.Parameters = make(map[string]string)
			}
			config.ScanConfig.Parameters["scan_name"] = args[i+1]
			i++
			
		default:
			return nil, fmt.Errorf("unknown argument: %s", arg)
		}
	}
	
	// Validate required fields
	if config.Pattern.Time == "" {
		return nil, fmt.Errorf("--time is required")
	}
	
	if config.Name == "" {
		return nil, fmt.Errorf("--name is required")
	}
	
	if config.ScanConfig.ScanType == "" {
		return nil, fmt.Errorf("scan target is required (--url, --url-list, or --nmap)")
	}
	
	// Validate schedule-specific requirements
	switch scheduleType {
	case "weekly":
		if len(config.Pattern.Days) == 0 {
			return nil, fmt.Errorf("--days is required for weekly schedules")
		}
	case "monthly":
		if config.Pattern.DayOfMonth == 0 {
			return nil, fmt.Errorf("--day is required for monthly schedules")
		}
	}
	
	return config, nil
}

// formatPattern formats a schedule pattern for display
func (sc *ScheduleCommand) formatPattern(schedule *Schedule) string {
	switch schedule.Type {
	case "daily":
		return fmt.Sprintf("Daily at %s", schedule.Pattern.Time)
	case "weekly":
		days := strings.Join(schedule.Pattern.Days, ", ")
		return fmt.Sprintf("Weekly on %s at %s", days, schedule.Pattern.Time)
	case "monthly":
		if schedule.Pattern.DayOfMonth == -1 {
			return fmt.Sprintf("Monthly on last day at %s", schedule.Pattern.Time)
		} else {
			return fmt.Sprintf("Monthly on day %d at %s", schedule.Pattern.DayOfMonth, schedule.Pattern.Time)
		}
	}
	return "Unknown pattern"
}

// CreateConfig holds configuration for creating a schedule
type CreateConfig struct {
	Name       string
	Pattern    Pattern
	ScanConfig ScanConfig
}

// HandleTestCommand handles schedule testing (dry-run)
func (sc *ScheduleCommand) HandleTestCommand(args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(color.Output, "%v Schedule ID required for testing\n", red(" [-] ERROR:"))
		fmt.Fprintf(color.Output, "%v Usage: burp-cli schedule test <schedule-id>\n", cyan(" [i] INFO:"))
		return nil
	}
	
	scheduleID := args[0]
	
	// Load the schedule
	schedules, err := sc.storage.LoadSchedules()
	if err != nil {
		return fmt.Errorf("failed to load schedules: %v", err)
	}
	
	var targetSchedule *Schedule
	for _, schedule := range schedules {
		if schedule.ID == scheduleID {
			targetSchedule = schedule
			break
		}
	}
	
	if targetSchedule == nil {
		fmt.Fprintf(color.Output, "%v Schedule not found: %s\n", red(" [-] ERROR:"), scheduleID)
		return nil
	}
	
	fmt.Fprintf(color.Output, "%v Testing Schedule (Dry-Run Mode)\n", cyan(" [i] INFO:"))
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Schedule Details:\n", greenBG(" [*] SCHEDULE:"))
	fmt.Fprintf(color.Output, "  • ID: %s\n", targetSchedule.ID)
	fmt.Fprintf(color.Output, "  • Name: %s\n", targetSchedule.Name)
	fmt.Fprintf(color.Output, "  • Type: %s\n", targetSchedule.Type)
	fmt.Fprintf(color.Output, "  • Pattern: %s\n", sc.formatPattern(targetSchedule))
	fmt.Fprintf(color.Output, "  • Target: %s\n", targetSchedule.ScanConfig.Target)
	fmt.Fprintf(color.Output, "\n")
	
	// Validate schedule configuration
	if err := targetSchedule.Validate(); err != nil {
		fmt.Fprintf(color.Output, "%v Schedule validation failed: %v\n", red(" [-] ERROR:"), err)
		return nil
	}
	
	fmt.Fprintf(color.Output, "%v Schedule validation: PASSED\n", green(" [+] SUCCESS:"))
	
	// Calculate next run time
	calc := NewCronCalculator()
	nextRun, err := calc.CalculateNextRun(targetSchedule, time.Now())
	if err != nil {
		fmt.Fprintf(color.Output, "%v Failed to calculate next run: %v\n", red(" [-] ERROR:"), err)
		return nil
	}
	
	fmt.Fprintf(color.Output, "%v Next execution time: %s\n", green(" [+] SUCCESS:"), nextRun.Format("2006-01-02 15:04:05 MST"))
	
	// Show what command would be executed
	fmt.Fprintf(color.Output, "\n%v Command that would be executed:\n", greenBG(" [*] COMMAND:"))
	
	// Build command parameters
	var cmdParts []string
	cmdParts = append(cmdParts, "./burp-cli")
	
	// Add scan type
	switch targetSchedule.ScanConfig.ScanType {
	case "url":
		cmdParts = append(cmdParts, "-s", targetSchedule.ScanConfig.Target)
	case "url_list":
		cmdParts = append(cmdParts, "-sl", targetSchedule.ScanConfig.Target)
	case "nmap":
		cmdParts = append(cmdParts, "-sn", targetSchedule.ScanConfig.Target)
	}
	
	// Add other parameters
	for key, value := range targetSchedule.ScanConfig.Parameters {
		switch key {
		case "config_number":
			cmdParts = append(cmdParts, "-cn", value)
		case "burp_config":
			cmdParts = append(cmdParts, "-bc", value)
		case "auto_export":
			if value == "true" {
				cmdParts = append(cmdParts, "-a")
			}
		case "export_dir":
			cmdParts = append(cmdParts, "-e", value)
		case "scan_name":
			cmdParts = append(cmdParts, "-sname", value)
		}
	}
	
	fmt.Fprintf(color.Output, "  %s\n", strings.Join(cmdParts, " "))
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Dry-run completed successfully. No actual scan was executed.\n", green(" [+] SUCCESS:"))
	
	return nil
}

// HandleDaemonCommand handles scheduler daemon operations
func (sc *ScheduleCommand) HandleDaemonCommand(args []string) error {
	foreground := false
	
	// Parse daemon arguments
	for _, arg := range args {
		switch arg {
		case "--foreground", "-f":
			foreground = true
		case "--help", "-h":
			return sc.ShowDaemonHelp()
		default:
			fmt.Fprintf(color.Output, "%v Unknown daemon option: %s\n", red(" [-] ERROR:"), arg)
			return sc.ShowDaemonHelp()
		}
	}
	
	fmt.Fprintf(color.Output, "%v Starting Scheduler Daemon\n", cyan(" [i] INFO:"))
	
	if foreground {
		fmt.Fprintf(color.Output, "%v Running in foreground mode (Ctrl+C to stop)\n", cyan(" [i] INFO:"))
		return sc.runDaemonForeground()
	} else {
		fmt.Fprintf(color.Output, "%v Running in background mode\n", cyan(" [i] INFO:"))
		return sc.runDaemonBackground()
	}
}

// ShowDaemonHelp displays help for daemon command
func (sc *ScheduleCommand) ShowDaemonHelp() error {
	fmt.Fprintf(color.Output, "%v Scheduler Daemon Help:\n", cyan(" [i] INFO:"))
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Usage:\n", greenBG(" [*] USAGE:"))
	fmt.Fprintf(color.Output, "  burp-cli schedule daemon [options]\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Options:\n", greenBG(" [*] OPTIONS:"))
	fmt.Fprintf(color.Output, "  --foreground, -f    Run in foreground (default: background)\n")
	fmt.Fprintf(color.Output, "  --help, -h          Show this help\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "%v Examples:\n", greenBG(" [*] EXAMPLES:"))
	fmt.Fprintf(color.Output, "  # Run daemon in background\n")
	fmt.Fprintf(color.Output, "  burp-cli schedule daemon\n")
	fmt.Fprintf(color.Output, "\n")
	fmt.Fprintf(color.Output, "  # Run daemon in foreground (for debugging)\n")
	fmt.Fprintf(color.Output, "  burp-cli schedule daemon --foreground\n")
	
	return nil
}

// runDaemonForeground runs the scheduler daemon in foreground mode
func (sc *ScheduleCommand) runDaemonForeground() error {
	fmt.Fprintf(color.Output, "%v Scheduler daemon started in foreground mode\n", green(" [+] SUCCESS:"))
	fmt.Fprintf(color.Output, "%v Press Ctrl+C to stop the daemon\n", cyan(" [i] INFO:"))
	
	// Create a simple scheduler loop
	ticker := time.NewTicker(1 * time.Minute) // Check every minute
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if err := sc.checkAndExecuteSchedules(); err != nil {
				fmt.Fprintf(color.Output, "%v Scheduler error: %v\n", red(" [-] ERROR:"), err)
			}
		}
	}
}

// runDaemonBackground runs the scheduler daemon in background mode
func (sc *ScheduleCommand) runDaemonBackground() error {
	fmt.Fprintf(color.Output, "%v Background daemon mode not fully implemented yet\n", yellow(" [!] WARNING:"))
	fmt.Fprintf(color.Output, "%v Use --foreground mode for now\n", cyan(" [i] INFO:"))
	fmt.Fprintf(color.Output, "%v Example: burp-cli schedule daemon --foreground\n", cyan(" [i] INFO:"))
	
	return nil
}

// checkAndExecuteSchedules checks all schedules and executes those that are due
func (sc *ScheduleCommand) checkAndExecuteSchedules() error {
	schedules, err := sc.storage.LoadSchedules()
	if err != nil {
		return fmt.Errorf("failed to load schedules: %v", err)
	}
	
	now := time.Now()
	calc := NewCronCalculator()
	
	for _, schedule := range schedules {
		if !schedule.Enabled {
			continue
		}
		
		// Check if it's time to run this schedule
		if now.After(schedule.NextRun) || now.Equal(schedule.NextRun) {
			fmt.Fprintf(color.Output, "%v Executing scheduled scan: %s\n", green(" [+] EXECUTING:"), schedule.Name)
			
			// Execute the schedule (this would integrate with existing burp-cli scan logic)
			if err := sc.executeSchedule(schedule); err != nil {
				fmt.Fprintf(color.Output, "%v Failed to execute schedule %s: %v\n", red(" [-] ERROR:"), schedule.Name, err)
			} else {
				fmt.Fprintf(color.Output, "%v Successfully executed schedule: %s\n", green(" [+] SUCCESS:"), schedule.Name)
			}
			
			// Update last run time and calculate next run
			now := time.Now()
			schedule.LastRun = &now
			
			nextRun, err := calc.CalculateNextRun(schedule, now)
			if err != nil {
				fmt.Fprintf(color.Output, "%v Failed to calculate next run for %s: %v\n", red(" [-] ERROR:"), schedule.Name, err)
				continue
			}
			
			schedule.NextRun = nextRun
			
			// Save updated schedule
			if err := sc.storage.UpdateSchedule(schedule); err != nil {
				fmt.Fprintf(color.Output, "%v Failed to update schedule %s: %v\n", red(" [-] ERROR:"), schedule.Name, err)
			}
			
			fmt.Fprintf(color.Output, "%v Next run for %s: %s\n", cyan(" [i] INFO:"), schedule.Name, nextRun.Format("2006-01-02 15:04:05 MST"))
		}
	}
	
	return nil
}

// executeSchedule executes a single schedule (placeholder for actual implementation)
func (sc *ScheduleCommand) executeSchedule(schedule *Schedule) error {
	// This is a placeholder - in a full implementation, this would:
	// 1. Build the appropriate burp-cli command
	// 2. Execute it using the existing burp-cli scan functions
	// 3. Handle the results and exports
	
	fmt.Fprintf(color.Output, "%v Schedule execution is a placeholder in this version\n", yellow(" [!] WARNING:"))
	fmt.Fprintf(color.Output, "%v Would execute: %s scan on %s\n", cyan(" [i] INFO:"), schedule.Type, schedule.ScanConfig.Target)
	
	// Simulate execution time
	time.Sleep(2 * time.Second)
	
	return nil
}