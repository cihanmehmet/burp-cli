package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/integrii/flaggy"
	"github.com/joanbono/color"
	"github.com/tidwall/gjson"

	"burp-cli/modules/commander"
	"burp-cli/modules/configure"
	"burp-cli/modules/nmap"
	"burp-cli/modules/reporter"
	"burp-cli/modules/scanner"
	"burp-cli/modules/scheduler"
)

// Defining colors
var yellow = color.New(color.Bold, color.FgYellow).SprintfFunc()
var red = color.New(color.Bold, color.FgRed).SprintfFunc()
var cyan = color.New(color.Bold, color.FgCyan).SprintfFunc()
var green = color.New(color.Bold, color.FgGreen).SprintfFunc()

var VERSION = `1.2.0`

//var BurpAPI, username, password, ApiToken string
var target, port string = "127.0.0.1", "1337"
var export string
var username, password string = "", ""
var key string = ""
var description string = ""
var metrics, issues bool = false, false
var scan, scan_id, scanList, nmapScan string
var description_names bool = false
var autoExport bool = false
var listConfigs bool = false
// v1.1.3: Added scan configuration and scope management parameters
var scanConfig, scopeInclude, scopeExclude, protocolOption string
// v1.1.4: Added custom configuration file support
var customConfigFile string
// v1.1.5: Added Burp ConfigLibrary configuration name support
var burpConfigName string
// v1.1.6: Added configuration number shortcut support
var configNumber int
// v1.1.7: Added OpenAPI compliance features
var scanName, resourcePool, callbackURL string
var advancedScope bool
var recordedLoginScript string
// v1.1.8: Added scheduler system variables
var scheduleCommand, scheduleType, scheduleTime, scheduleDays string
var scheduleDayOfMonth int
var scheduleName string
var daemonMode, foregroundMode bool
// v1.2.0: Added report generation feature
var reportInput, reportOutput, reportFormat string
// v1.2.1: Added scan listing and bulk export features
var listScans, listAndExportAll, importFromBurp bool
var clearOldScans int

func init() {
	flaggy.SetName("burp-cli")
	flaggy.SetDescription(`Interact with Burp Suite Professional REST API

USAGE EXAMPLES:

  Scanning:
    burp-cli -s "https://example.com" -a                    # Single URL scan with auto-export
    burp-cli -sl urls.txt -a                                # Scan multiple URLs
    burp-cli -sn nmap.xml -a                                # Scan from Nmap XML
    burp-cli -s "https://example.com" -U admin -P pass -a   # Authenticated scan

  Configuration:
    burp-cli -lc                                            # List available configs
    burp-cli -s "https://example.com" -cn 3 -a              # Use config by number
    burp-cli -s "https://example.com" -bc "SQL Injection"   # Use Burp config

  Scan Results:
    burp-cli -S 8 -M                                        # Get scan metrics
    burp-cli -S 8 -I                                        # Get scan issues
    burp-cli -S 8 -e /tmp                                   # Export to directory (JSON + HTML)

  Report Generation:
    burp-cli -ri Burp_export.json                           # Generate Burp-style HTML report
    burp-cli -ri Burp_export.json -rf classic               # Generate Classic-style report
    burp-cli -ri Burp_export.json -rf both                  # Generate both formats

  Scan Management:
    burp-cli -L                                             # List all scans (auto-syncs with Burp)
    burp-cli -LA                                            # List and export all (auto-syncs first)
    burp-cli --import-from-burp -L                          # Verbose import from Burp and list
    burp-cli --clear-old-scans 30                           # Clear scans older than 30 days
    
    Note: -L and -LA automatically sync with Burp API if available
          No need to manually import or clear history!

  Scheduler:
    burp-cli schedule create daily --time 21:00 --url "https://example.com" --auto-export
    burp-cli schedule list                                  # List all schedules
    burp-cli schedule daemon --foreground                   # Run scheduler daemon

For more examples: https://github.com/cihanmehmet/burp-cli

Version Info: burp-cli -V  or  burp-cli --version


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  REQUIREMENTS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • Burp Suite Professional (Community Edition NOT supported)
  • REST API must be enabled: Settings → Suite → REST API → "Service is running"
  • Default: http://127.0.0.1:1337
  • Docs: https://portswigger.net/burp/documentation/desktop/settings/suite/rest-api


(Subcommands and Flags are listed below)`)
	flaggy.DefaultParser.ShowVersionWithVersionFlag = false

	flaggy.String(&target, "t", "target", "Burp Address. Default 127.0.0.1")
	flaggy.String(&port, "p", "port", "Burp API Port. Default 1337")

	flaggy.String(&username, "U", "username", "Username for an authenticated scan")
	flaggy.String(&password, "P", "password", "Password for an authenticated scan")

	flaggy.String(&scan, "s", "scan", "URLs to scan")
	flaggy.String(&scan_id, "S", "scan-id", "Scanned URL identifier")

	flaggy.String(&nmapScan, "sn", "scan-nmap", "Nmap xml file to scan")
	flaggy.String(&scanList, "sl", "scan-list", "File with hosts/Ip's to scan")

	flaggy.Bool(&metrics, "M", "metrics", "Provides metrics for a given task")
	flaggy.String(&description, "D", "description", "Provides description for a given issue")
	flaggy.Bool(&description_names, "d", "description-names", "Returns vulnerability names from PortSwigger")
	flaggy.Bool(&issues, "I", "issues", "Provides issues for a given task")
	flaggy.String(&export, "e", "export", "Export issues' json.")
	flaggy.Bool(&autoExport, "a", "auto-export", "Automatically export scan results when scan completes")
	flaggy.Bool(&listConfigs, "lc", "list-configs", "List available scan configurations")
	
	// v1.1.3: Scan configuration and scope management flags
	flaggy.String(&scanConfig, "sc", "scan-config", "Scan configuration name (e.g., 'Crawl and Audit - Fast', 'Audit only - Fast')")
	flaggy.String(&scopeInclude, "si", "scope-include", "Comma-separated list of URLs/patterns to include in scope")
	flaggy.String(&scopeExclude, "se", "scope-exclude", "Comma-separated list of URLs/patterns to exclude from scope")
	flaggy.String(&protocolOption, "po", "protocol-option", "Protocol option: 'httpAndHttps' or 'specified' (default: httpAndHttps)")
	// v1.1.4: Custom configuration file support
	flaggy.String(&customConfigFile, "cf", "config-file", "Path to custom Burp configuration JSON file (exported from Burp Suite)")
	// v1.1.5: Burp ConfigLibrary configuration name support
	flaggy.String(&burpConfigName, "bc", "burp-config", "Burp Suite ConfigLibrary configuration name (auto-detected from ConfigLibrary)")
	// v1.1.6: Configuration number shortcut support
	flaggy.Int(&configNumber, "cn", "config-number", "Configuration number from list (use -lc to see numbers)")
	
	// v1.1.7: OpenAPI compliance features
	flaggy.String(&scanName, "sname", "scan-name", "Custom name for the scan (helps with organization)")
	flaggy.String(&resourcePool, "rp", "resource-pool", "Resource pool to use for the scan")
	flaggy.String(&callbackURL, "cb", "callback", "Callback URL to receive scan completion notifications")
	flaggy.Bool(&advancedScope, "as", "advanced-scope", "Use advanced scope with protocol/port/file specifications")
	flaggy.String(&recordedLoginScript, "rls", "recorded-login", "Path to recorded login script file")

	flaggy.String(&key, "k", "key", "Api Key")
	// Version flag removed - handled before flaggy.Parse() in main()
	
	// v1.2.0: Report generation flags
	flaggy.String(&reportInput, "ri", "report-input", "Burp JSON export file for report generation")
	flaggy.String(&reportOutput, "ro", "report-output", "Output HTML report file (default: burp_security_report.html)")
	flaggy.String(&reportFormat, "rf", "report-format", "Report format: burp, classic, or both (default: burp)")
	
	// v1.2.1: Scan listing and bulk export flags
	flaggy.Bool(&listScans, "L", "list-scans", "List all tracked scans with their URLs and status")
	flaggy.Bool(&listAndExportAll, "LA", "list-and-export-all", "List all scans and export HTML reports for each")
	flaggy.Bool(&importFromBurp, "", "import-from-burp", "Import existing scans from Burp API (scans ID 1-50)")
	flaggy.Int(&clearOldScans, "", "clear-old-scans", "Clear scan records older than specified days (e.g., --clear-old-scans 30)")
	
	// Hidden flag for adding test scans
	flaggy.String(&addTestScan, "", "add-test-scan", "Add a test scan to history (format: scanID,url)")
	
	flaggy.SetVersion(VERSION)
	// Parse() moved to main() to allow early version check
}

var addTestScan string

// Helper function to extract scan ID from Location header
func extractScanID(location string) string {
	parts := strings.Split(location, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// Helper function to generate filename from URL
func generateFilename(scanURL string) string {
	parsedURL, err := url.Parse(scanURL)
	if err != nil {
		return "scan_export.json"
	}
	
	// Create filename from host and path
	filename := strings.ReplaceAll(parsedURL.Host, ":", "_")
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		path := strings.Trim(parsedURL.Path, "/")
		path = strings.ReplaceAll(path, "/", "_")
		filename = filename + "_" + path
	}
	
	// Add timestamp
	timestamp := time.Now().Format("20060102_150405")
	filename = filename + "_" + timestamp + ".json"
	
	return filename
}

// Helper function to generate HTML report filename from URL
func generateHTMLFilename(scanURL string) string {
	// Check if it's a generic scan ID (e.g., "scan_3")
	if strings.HasPrefix(scanURL, "scan_") {
		timestamp := time.Now().Format("20060102_150405")
		return "burp_scan_report_" + timestamp + ".html"
	}
	
	parsedURL, err := url.Parse(scanURL)
	if err != nil {
		return "scan_report_" + time.Now().Format("20060102_150405") + ".html"
	}
	
	// Create filename from host and path
	filename := strings.ReplaceAll(parsedURL.Host, ":", "_")
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		path := strings.Trim(parsedURL.Path, "/")
		path = strings.ReplaceAll(path, "/", "_")
		filename = filename + "_" + path
	}
	
	// Add timestamp
	timestamp := time.Now().Format("20060102_150405")
	filename = filename + "_" + timestamp + ".html"
	
	return filename
}

// Helper function to generate HTML report from JSON export
func generateHTMLReportFromJSON(jsonFilePath, scanURL, exportDir string) {
	htmlFilename := generateHTMLFilename(scanURL)
	htmlFilePath := exportDir + "/" + htmlFilename
	
	fmt.Fprintf(color.Output, "%v Generating HTML report: %v\n", cyan(" [i] INFO:"), htmlFilename)
	
	err := reporter.GenerateReport(jsonFilePath, htmlFilePath, "burp")
	if err != nil {
		fmt.Fprintf(color.Output, "%v Failed to generate HTML report: %v\n", red(" [-] ERROR:"), err)
	} else {
		fmt.Fprintf(color.Output, "%v HTML report generated: %v\n", green(" [+] SUCCESS:"), htmlFilePath)
	}
}

// Create export directory if it doesn't exist
func createExportDir() string {
	exportDir := "burp-export"
	
	if _, err := os.Stat(exportDir); os.IsNotExist(err) {
		err := os.MkdirAll(exportDir, 0755)
		if err != nil {
			fmt.Fprintf(color.Output, "%v Failed to create export directory: %v\n", red(" [-] ERROR:"), err)
			return ""
		}
		fmt.Fprintf(color.Output, "%v Created export directory: %v\n", green(" [+] SUCCESS:"), exportDir)
	}
	
	return exportDir
}

// Monitor scan and export when complete
func monitorAndExport(target, port, scanID, scanURL, exportDir, apikey string) {
	fmt.Fprintf(color.Output, "%v Monitoring scan %v...\n", cyan(" [i] INFO:"), scanID)
	
	// Track this scan
	tracker, err := scanner.NewScanTracker()
	if err == nil {
		tracker.AddScan(scanID, scanURL, "", "")
	}
	
	for {
		status, err := configure.CheckScanStatus(target, port, scanID, apikey)
		if err != nil {
			fmt.Fprintf(color.Output, "%v Error checking scan status: %v\n", red(" [-] ERROR:"), err)
			if tracker != nil {
				tracker.UpdateScanStatus(scanID, "failed")
			}
			return
		}
		
		fmt.Fprintf(color.Output, "%v Scan status: %v\n", cyan(" [i] INFO:"), status)
		
		// Update scan status in tracker
		if tracker != nil {
			tracker.UpdateScanStatus(scanID, status)
		}
		
		if status == "succeeded" || status == "failed" {
			fmt.Fprintf(color.Output, "%v Scan completed with status: %v\n", green(" [+] SUCCESS:"), status)
			
			if status == "succeeded" && exportDir != "" {
				filename := generateFilename(scanURL)
				jsonFilePath := exportDir + "/" + filename
				commander.GetScanWithFilename(target, port, scanID, exportDir, filename, apikey)
				
				// v1.2.0: Automatically generate HTML report from JSON export
				generateHTMLReportFromJSON(jsonFilePath, scanURL, exportDir)
			}
			break
		}
		
		time.Sleep(10 * time.Second)
	}
}

func main() {
	// Handle version and scheduler commands before flaggy parsing
	if len(os.Args) >= 2 {
		arg := os.Args[1]
		
		// Handle version: -V or --version
		if arg == "-V" || arg == "--version" {
			fmt.Println()
			fmt.Fprintf(color.Output, "  %v\n", green("burp-cli"))
			fmt.Fprintf(color.Output, "  Version: %v\n", cyan(VERSION))
			fmt.Fprintf(color.Output, "  GitHub:  https://github.com/cihanmehmet/burp-cli\n")
			fmt.Fprintf(color.Output, "  License: MIT\n")
			fmt.Println()
			os.Exit(0)
		}
		
		// Handle scheduler
		if arg == "schedule" {
			cli, err := scheduler.NewScheduleCLI()
			if err != nil {
				fmt.Fprintf(color.Output, "%v Failed to initialize scheduler: %v\n", red(" [-] ERROR:"), err)
				os.Exit(1)
			}
			if err := cli.HandleScheduleCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(color.Output, "%v Scheduler error: %v\n", red(" [-] ERROR:"), err)
				os.Exit(1)
			}
			return
		}
	}
	
	// Parse flags after handling version/scheduler
	flaggy.Parse()

	// Check how many args are provided
	if len(os.Args) < 2 {
		fmt.Fprintf(color.Output, "\n %v No argument provided. Try with %v.\n\n", cyan("[i] INFO:"), green("burp-cli -h"))
		os.Exit(0)
	}


	
	// v1.2.1: Handle scan listing and management
	if listScans || listAndExportAll || clearOldScans > 0 || addTestScan != "" || importFromBurp {
		handleScanManagement()
		return
	}
	
	if configure.CheckBurp(target, port, key) == true {
		fmt.Fprintf(color.Output, "%v Found Burp API endpoint on %v.\n", green(" [+] SUCCESS:"), target+":"+port)
	} else {
		fmt.Fprintf(color.Output, "%v No Burp API endpoint found on %v.\n", red(" [-] ERROR:"), target+":"+port)
		os.Exit(0)
	}

	// v1.1.7: Smart export directory management
	if autoExport {
		// If user specified export directory, use it; otherwise use burp-export
		if export == "" {
			export = createExportDir() // Use default burp-export
		} else {
			// User specified directory, ensure it exists
			if _, err := os.Stat(export); os.IsNotExist(err) {
				err := os.MkdirAll(export, 0755)
				if err != nil {
					fmt.Fprintf(color.Output, "%v Failed to create export directory %v: %v\n", red(" [-] ERROR:"), export, err)
					autoExport = false
				} else {
					fmt.Fprintf(color.Output, "%v Using export directory: %v\n", green(" [+] SUCCESS:"), export)
				}
			}
		}
		
		if export == "" {
			fmt.Fprintf(color.Output, "%v Failed to setup export directory, disabling auto-export\n", red(" [-] ERROR:"))
			autoExport = false
		}
	}

	if nmapScan != "" {
		scanList, err := nmap.ParseNmap(nmapScan)
		if err != nil {
			fmt.Fprintf(color.Output, "%v  %v.\n", red(" [-] ERROR:"), err)
			os.Exit(0)
		}
		// v1.1.3+: Enhanced nmap scan processing with advanced configuration
		for _, scan := range scanList {
			var Location string
			// v1.1.7: Support for all advanced options including OpenAPI features in nmap scans
			if configNumber > 0 || burpConfigName != "" || customConfigFile != "" || scanConfig != "" || scopeInclude != "" || scopeExclude != "" || protocolOption != "" || scanName != "" || resourcePool != "" || callbackURL != "" || advancedScope || recordedLoginScript != "" {
				Location = configure.ScanConfigAdvanced(target, port, scan, username, password, key, scanConfig, scopeInclude, scopeExclude, protocolOption, customConfigFile, burpConfigName, configNumber, scanName, resourcePool, callbackURL, advancedScope, recordedLoginScript)
			} else {
				Location = configure.ScanConfig(target, port, scan, username, password, key)
			}
			
			if Location != "" {
				scanID := extractScanID(Location)
				fmt.Fprintf(color.Output, "%v Scanning %v with ID %v.\n", green(" [+] SUCCESS:"), scan, scanID)
				
				// v1.1.1: Auto-export with goroutines for parallel processing
				if autoExport {
					go monitorAndExport(target, port, scanID, scan, export, key)
				}
			} else {
				fmt.Fprintf(color.Output, "%v Can't start scan .\n", red(" [-] ERROR:"))
				os.Exit(0)
			}
		}
		
		// Wait for all scans to complete if auto-export is enabled
		if autoExport {
			fmt.Fprintf(color.Output, "%v Waiting for all scans to complete...\n", cyan(" [i] INFO:"))
			time.Sleep(5 * time.Second) // Give goroutines time to start
			for {
				time.Sleep(5 * time.Second)
			}
		}
	}

	if scanList != "" {
		targets := nmap.ParseFile(scanList)
		// v1.1.3+: Enhanced URL list processing with advanced configuration
		for _, scan := range targets {
			var Location string
			// v1.1.7: Support for all advanced options including OpenAPI features in URL list scans
			if configNumber > 0 || burpConfigName != "" || customConfigFile != "" || scanConfig != "" || scopeInclude != "" || scopeExclude != "" || protocolOption != "" || scanName != "" || resourcePool != "" || callbackURL != "" || advancedScope || recordedLoginScript != "" {
				Location = configure.ScanConfigAdvanced(target, port, scan, username, password, key, scanConfig, scopeInclude, scopeExclude, protocolOption, customConfigFile, burpConfigName, configNumber, scanName, resourcePool, callbackURL, advancedScope, recordedLoginScript)
			} else {
				Location = configure.ScanConfig(target, port, scan, username, password, key)
			}
			
			if Location != "" {
				scanID := extractScanID(Location)
				fmt.Fprintf(color.Output, "%v Scanning %v with ID %v.\n", green(" [+] SUCCESS:"), scan, scanID)
				
				// v1.1.1: Auto-export with goroutines for parallel processing
				if autoExport {
					go monitorAndExport(target, port, scanID, scan, export, key)
				}
			} else {
				fmt.Fprintf(color.Output, "%v Can't start scan over %s .\n", red(" [-] ERROR:"), scan)
			}
		}
		
		// Wait for all scans to complete if auto-export is enabled
		if autoExport {
			fmt.Fprintf(color.Output, "%v Waiting for all scans to complete...\n", cyan(" [i] INFO:"))
			time.Sleep(5 * time.Second)
			for {
				time.Sleep(5 * time.Second)
			}
		}
	}

	// v1.1.3+: Enhanced scan configuration with advanced options
	if scan != "" {
		var Location string
		// v1.1.7: Check for any advanced options including OpenAPI compliance features
		if configNumber > 0 || burpConfigName != "" || customConfigFile != "" || scanConfig != "" || scopeInclude != "" || scopeExclude != "" || protocolOption != "" || scanName != "" || resourcePool != "" || callbackURL != "" || advancedScope || recordedLoginScript != "" {
			Location = configure.ScanConfigAdvanced(target, port, scan, username, password, key, scanConfig, scopeInclude, scopeExclude, protocolOption, customConfigFile, burpConfigName, configNumber, scanName, resourcePool, callbackURL, advancedScope, recordedLoginScript)
		} else {
			Location = configure.ScanConfig(target, port, scan, username, password, key)
		}
		
		if Location != "" {
			scanID := extractScanID(Location)
			fmt.Fprintf(color.Output, "%v Scanning %v with ID %v.\n", green(" [+] SUCCESS:"), scan, scanID)
			
			// v1.1.1: Auto-export functionality
			if autoExport {
				monitorAndExport(target, port, scanID, scan, export, key)
			}
		} else {
			fmt.Fprintf(color.Output, "%v Can't start scan .\n", red(" [-] ERROR:"))
			os.Exit(0)
		}
	}

	if scan == "" && scan_id != "" && metrics == true && issues == false {
		commander.GetMetrics(target, port, scan_id, key)
	} else if scan == "" && scan_id != "" && metrics == true && issues == true {
		exportDir := export
		if exportDir == "" {
			exportDir = createExportDir()
		}
		commander.GetScan(target, port, scan_id, exportDir, key)
		commander.GetMetrics(target, port, scan_id, key)
		
		// v1.2.0: Automatically generate HTML report from JSON export
		jsonFilePath := exportDir + "/Burp_export.json"
		if _, err := os.Stat(jsonFilePath); err == nil {
			genericURL := "scan_" + scan_id
			generateHTMLReportFromJSON(jsonFilePath, genericURL, exportDir)
		}
	} else if scan == "" && scan_id != "" && metrics == false {
		exportDir := export
		if exportDir == "" {
			exportDir = createExportDir()
		}
		commander.GetScan(target, port, scan_id, exportDir, key)
		
		// v1.2.0: Automatically generate HTML report from JSON export
		jsonFilePath := exportDir + "/Burp_export.json"
		if _, err := os.Stat(jsonFilePath); err == nil {
			genericURL := "scan_" + scan_id
			generateHTMLReportFromJSON(jsonFilePath, genericURL, exportDir)
		}
	}

	if description != "" {
		configure.GetDescription(target, port, description, key)
	}
	if description_names == true {
		configure.GetNames(target, port, key)
	}
	// v1.1.3: List available scan configurations
	if listConfigs == true {
		configure.ListScanConfigurations(target, port, key)
	}
	
	// v1.2.0: Report generation from Burp JSON export
	if reportInput != "" {
		if reportOutput == "" {
			reportOutput = "burp_security_report.html"
		}
		if reportFormat == "" {
			reportFormat = "burp"
		}
		
		fmt.Fprintf(color.Output, "%v Generating HTML report from %v\n", cyan(" [i] INFO:"), reportInput)
		err := reporter.GenerateReport(reportInput, reportOutput, reportFormat)
		if err != nil {
			fmt.Fprintf(color.Output, "%v Failed to generate report: %v\n", red(" [-] ERROR:"), err)
			os.Exit(1)
		}
		fmt.Fprintf(color.Output, "%v Report generated successfully: %v\n", green(" [+] SUCCESS:"), reportOutput)
	}
}

// handleScanManagement handles scan listing and bulk export operations
func handleScanManagement() {
	tracker, err := scanner.NewScanTracker()
	if err != nil {
		fmt.Fprintf(color.Output, "%v Failed to initialize scan tracker: %v\n", red(" [-] ERROR:"), err)
		os.Exit(1)
	}
	
	// Auto-sync: When listing scans, automatically sync with Burp API if available
	// This keeps the history up-to-date without manual --import-from-burp
	if (listScans || listAndExportAll) && !importFromBurp {
		// Try to sync with Burp API silently
		if configure.CheckBurp(target, port, key) {
			// Burp API is available, sync automatically
			syncScansFromBurp(tracker, target, port, key, false) // false = silent mode
		}
		// If Burp API not available, just show cached history (offline mode)
	}
	
	// Handle explicit import from Burp (verbose mode)
	if importFromBurp {
		fmt.Fprintf(color.Output, "%v Importing scans from Burp API...\n", cyan(" [i] INFO:"))
		
		// Check Burp API connection
		if !configure.CheckBurp(target, port, key) {
			fmt.Fprintf(color.Output, "%v Burp API not available. Cannot import scans.\n", red(" [-] ERROR:"))
			fmt.Fprintf(color.Output, "  Make sure Burp Suite is running and API is enabled.\n")
			os.Exit(1)
		}
		
		imported := syncScansFromBurp(tracker, target, port, key, true) // true = verbose mode
		
		if imported == 0 {
			fmt.Fprintf(color.Output, "%v No scans found in Burp API\n", yellow(" [!] WARNING:"))
			fmt.Fprintf(color.Output, "  Try running some scans in Burp Suite first\n")
		} else {
			fmt.Fprintf(color.Output, "%v Successfully imported %d scans\n", green(" [+] SUCCESS:"), imported)
		}
		
		// If only importing, optionally list
		if !listScans && !listAndExportAll {
			fmt.Fprintf(color.Output, "%v Use -L to list all scans\n", cyan(" [i] INFO:"))
			return
		}
	}
	
	// Handle add test scan
	if addTestScan != "" {
		parts := strings.Split(addTestScan, ",")
		if len(parts) != 2 {
			fmt.Fprintf(color.Output, "%v Invalid format. Use: scanID,url\n", red(" [-] ERROR:"))
			fmt.Fprintf(color.Output, "  Example: --add-test-scan 3,https://example.com\n")
			os.Exit(1)
		}
		
		scanID := strings.TrimSpace(parts[0])
		url := strings.TrimSpace(parts[1])
		
		if err := tracker.AddScan(scanID, url, "", ""); err != nil {
			fmt.Fprintf(color.Output, "%v Failed to add test scan: %v\n", red(" [-] ERROR:"), err)
			os.Exit(1)
		}
		
		fmt.Fprintf(color.Output, "%v Test scan added: ID=%v, URL=%v\n", green(" [+] SUCCESS:"), scanID, url)
		
		// If only adding test scan, optionally list
		if !listScans && !listAndExportAll {
			fmt.Fprintf(color.Output, "%v Use -L to list all scans\n", cyan(" [i] INFO:"))
			return
		}
	}
	
	// Handle clear old scans
	if clearOldScans > 0 {
		fmt.Fprintf(color.Output, "%v Clearing scans older than %d days...\n", cyan(" [i] INFO:"), clearOldScans)
		if err := tracker.ClearOldScans(clearOldScans); err != nil {
			fmt.Fprintf(color.Output, "%v Failed to clear old scans: %v\n", red(" [-] ERROR:"), err)
			os.Exit(1)
		}
		fmt.Fprintf(color.Output, "%v Old scans cleared successfully\n", green(" [+] SUCCESS:"))
		
		// If only clearing, exit
		if !listScans && !listAndExportAll {
			return
		}
	}
	
	// Get all scans
	scans := tracker.GetAllScans()
	
	if len(scans) == 0 {
		fmt.Fprintf(color.Output, "%v No scans found in history\n", cyan(" [i] INFO:"))
		fmt.Fprintf(color.Output, "  Scans are automatically tracked when you start them with burp-cli\n")
		return
	}
	
	// Display scan list
	fmt.Fprintf(color.Output, "\n%v Tracked Scans (%d total):\n", cyan(" [i] INFO:"), len(scans))
	fmt.Fprintf(color.Output, "═══════════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(color.Output, "%-6s %-40s %-12s %-20s\n", "Scan ID", "URL", "Status", "Start Time")
	fmt.Fprintf(color.Output, "───────────────────────────────────────────────────────────────────────────────────\n")
	
	for _, scan := range scans {
		// Truncate URL if too long
		displayURL := scan.URL
		if len(displayURL) > 38 {
			displayURL = displayURL[:35] + "..."
		}
		
		// Format time
		timeStr := scan.StartTime.Format("2006-01-02 15:04")
		
		// Color code status
		statusColor := cyan
		switch scan.Status {
		case "succeeded":
			statusColor = green
		case "failed":
			statusColor = red
		case "running":
			statusColor = yellow
		}
		
		fmt.Fprintf(color.Output, "%-6s %-40s %v %-20s\n", 
			scan.ScanID, displayURL, statusColor(scan.Status), timeStr)
	}
	
	fmt.Fprintf(color.Output, "═══════════════════════════════════════════════════════════════════════════════════\n\n")
	
	// Handle list and export all
	if listAndExportAll {
		fmt.Fprintf(color.Output, "%v Starting bulk export for all scans...\n\n", cyan(" [i] INFO:"))
		
		// Create export directory
		exportDir := "bulk-export"
		if err := os.MkdirAll(exportDir, 0755); err != nil {
			fmt.Fprintf(color.Output, "%v Failed to create export directory: %v\n", red(" [-] ERROR:"), err)
			os.Exit(1)
		}
		
		// Check Burp API connection for export
		if !configure.CheckBurp(target, port, key) {
			fmt.Fprintf(color.Output, "%v Burp API not available. Cannot export scans.\n", red(" [-] ERROR:"))
			fmt.Fprintf(color.Output, "  Make sure Burp Suite is running and API is enabled.\n")
			os.Exit(1)
		}
		
		successCount := 0
		failCount := 0
		
		for i, scan := range scans {
			fmt.Fprintf(color.Output, "[%d/%d] Processing Scan ID %s (%s)...\n", 
				i+1, len(scans), scan.ScanID, scan.URL)
			
			// Export JSON from Burp API
			jsonFile := filepath.Join(exportDir, fmt.Sprintf("scan_%s.json", scan.ScanID))
			
			// Get scan data from Burp API
			if err := exportScanToJSON(scan.ScanID, jsonFile); err != nil {
				fmt.Fprintf(color.Output, "  %v Failed to export JSON: %v\n", red("✗"), err)
				failCount++
				continue
			}
			
			// Generate HTML report
			htmlFile := filepath.Join(exportDir, fmt.Sprintf("scan_%s_report.html", scan.ScanID))
			
			if err := reporter.GenerateReport(jsonFile, htmlFile, "burp"); err != nil {
				fmt.Fprintf(color.Output, "  %v JSON exported but HTML generation failed: %v\n", yellow("⚠"), err)
				failCount++
				continue
			}
			
			fmt.Fprintf(color.Output, "  %v JSON: %s\n", green("✓"), jsonFile)
			fmt.Fprintf(color.Output, "  %v HTML: %s\n\n", green("✓"), htmlFile)
			successCount++
		}
		
		fmt.Fprintf(color.Output, "═══════════════════════════════════════════════════════════════════════════════════\n")
		fmt.Fprintf(color.Output, "%v Bulk export completed: %v succeeded, %v failed\n", 
			green(" [+] SUCCESS:"), green(fmt.Sprintf("%d", successCount)), red(fmt.Sprintf("%d", failCount)))
		fmt.Fprintf(color.Output, "%v Reports saved to: %v\n", cyan(" [i] INFO:"), exportDir)
	}
}

// exportScanToJSON exports a scan's results to JSON file
func exportScanToJSON(scanID, outputFile string) error {
	// Create temp directory for export
	exportDir := filepath.Dir(outputFile)
	exportFilename := filepath.Base(outputFile)
	
	// Use commander.GetScanWithFilename to export directly to file
	// This function writes to exportFolder/exportFilename
	commander.GetScanWithFilename(target, port, scanID, exportDir, exportFilename, key)
	
	// Check if file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		return fmt.Errorf("export failed - file not created")
	}
	
	return nil
}

// syncScansFromBurp syncs scan history with Burp API
// verbose: if true, prints detailed import messages; if false, syncs silently
func syncScansFromBurp(tracker *scanner.ScanTracker, target, port, apikey string, verbose bool) int {
	imported := 0
	updated := 0
	
	// Try scan IDs from 1 to 50
	for i := 1; i <= 50; i++ {
		scanID := fmt.Sprintf("%d", i)
		
		// Try to get scan status
		status, err := configure.CheckScanStatus(target, port, scanID, apikey)
		if err != nil {
			// Scan doesn't exist, skip
			continue
		}
		
		// Check if already tracked
		existing := tracker.GetScanByID(scanID)
		
		if existing != nil {
			// Update status if changed
			if existing.Status != status {
				tracker.UpdateScanStatus(scanID, status)
				updated++
			}
			
			// Update URL if it was generic (scan_X) and we can get a real URL now
			if strings.HasPrefix(existing.URL, "scan_") {
				scanURL := getScanURL(target, port, scanID, apikey)
				if scanURL == "" {
					scanURL = getScanURLFromIssues(target, port, scanID, apikey)
				}
				if scanURL != "" && !strings.HasPrefix(scanURL, "scan_") {
					// Update with real URL
					existing.URL = scanURL
					tracker.UpdateScanStatus(scanID, status) // This saves the tracker
				}
			}
			continue
		}
		
		// New scan - get URL and add to tracker
		scanURL := getScanURL(target, port, scanID, apikey)
		if scanURL == "" {
			// If we can't get the URL, try to get it from issues
			scanURL = getScanURLFromIssues(target, port, scanID, apikey)
		}
		if scanURL == "" {
			scanURL = fmt.Sprintf("scan_%s", scanID)
		}
		
		// Add to tracker
		if err := tracker.AddScan(scanID, scanURL, "", ""); err == nil {
			// Update with correct status
			tracker.UpdateScanStatus(scanID, status)
			imported++
			if verbose {
				fmt.Fprintf(color.Output, "  %v Imported scan %s: %s (%s)\n", green("✓"), scanID, scanURL, status)
			}
		}
	}
	
	// Show sync summary only in verbose mode
	if verbose && (imported > 0 || updated > 0) {
		if imported > 0 && updated > 0 {
			fmt.Fprintf(color.Output, "%v Synced: %d new, %d updated\n", cyan(" [i] INFO:"), imported, updated)
		} else if imported > 0 {
			fmt.Fprintf(color.Output, "%v Added %d new scans\n", cyan(" [i] INFO:"), imported)
		} else if updated > 0 {
			fmt.Fprintf(color.Output, "%v Updated %d scans\n", cyan(" [i] INFO:"), updated)
		}
	}
	
	return imported
}

// getScanURL retrieves the URL from a scan
func getScanURL(target, port, scanID, apikey string) string {
	// Build endpoint URL
	var endpoint string
	if apikey != "" {
		endpoint = fmt.Sprintf("http://%s:%s/%s/v0.1/scan/%s", target, port, apikey, scanID)
	} else {
		endpoint = fmt.Sprintf("http://%s:%s/v0.1/scan/%s", target, port, scanID)
	}
	
	// Try to get scan data
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return ""
	}
	
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	
	bodyStr := string(body)
	
	// Use gjson to extract URL from scan_metrics.current_url
	currentURL := gjson.Get(bodyStr, "scan_metrics.current_url")
	if currentURL.Exists() && currentURL.String() != "" {
		url := currentURL.String()
		if strings.HasPrefix(url, "http") {
			return url
		}
	}
	
	// Fallback: Try to get URL from first issue event
	firstIssue := gjson.Get(bodyStr, "issue_events.0.issue.origin")
	if firstIssue.Exists() && firstIssue.String() != "" {
		url := firstIssue.String()
		if strings.HasPrefix(url, "http") {
			return url
		}
	}
	
	// Another fallback: Get from issue path
	issuePath := gjson.Get(bodyStr, "issue_events.0.issue.path")
	if issuePath.Exists() && issuePath.String() != "" {
		path := issuePath.String()
		if strings.HasPrefix(path, "http") {
			return path
		}
	}
	
	return ""
}

// getScanURLFromIssues tries to extract URL from scan issues
func getScanURLFromIssues(target, port, scanID, apikey string) string {
	// Build endpoint URL with issue_events parameter
	var endpoint string
	if apikey != "" {
		endpoint = fmt.Sprintf("http://%s:%s/%s/v0.1/scan/%s?issue_events=1", target, port, apikey, scanID)
	} else {
		endpoint = fmt.Sprintf("http://%s:%s/v0.1/scan/%s?issue_events=1", target, port, scanID)
	}
	
	// Try to get scan data
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return ""
	}
	
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	
	bodyStr := string(body)
	
	// Try to get URL from first issue's origin
	origin := gjson.Get(bodyStr, "issue_events.0.issue.origin")
	if origin.Exists() && origin.String() != "" {
		url := origin.String()
		if strings.HasPrefix(url, "http") {
			return url
		}
	}
	
	// Try to get from issue path
	path := gjson.Get(bodyStr, "issue_events.0.issue.path")
	if path.Exists() && path.String() != "" {
		urlPath := path.String()
		if strings.HasPrefix(urlPath, "http") {
			return urlPath
		}
	}
	
	return ""
}
