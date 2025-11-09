package configure

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	strip "github.com/grokify/html-strip-tags-go"
	"github.com/joanbono/color"
	"github.com/tidwall/gjson"
)

var yellow = color.New(color.Bold, color.FgYellow).SprintfFunc()
var red = color.New(color.Bold, color.FgRed).SprintfFunc()
var cyan = color.New(color.Bold, color.FgCyan).SprintfFunc()
var green = color.New(color.Bold, color.FgGreen).SprintfFunc()
var redBG = color.New(color.Bold, color.FgWhite, color.BgHiRed).SprintfFunc()
var cyanBG = color.New(color.Bold, color.FgBlack, color.BgHiCyan).SprintfFunc()
var yellowBG = color.New(color.Bold, color.FgBlack, color.BgHiYellow).SprintfFunc()
var greenBG = color.New(color.Bold, color.FgBlack, color.BgHiGreen).SprintfFunc()

// Skipping SSL verification
var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	//Proxy:           http.ProxyURL(proxyUrl),
}

var client = &http.Client{Timeout: time.Second * 5, Transport: tr}

// Check if BURP is alive and with API Ready to be used
func CheckBurp(target, port, apikey string) (response bool) {
	var endpoint string
	if apikey != "" {
		endpoint = "http://" + target + ":" + port + "/" + apikey + "/v0.1/"
	} else {
		endpoint = "http://" + target + ":" + port + "/v0.1/"
	}

	resp, err := client.Get(endpoint)

	if err != nil {
		return false
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 {
		return true
	} else {
		return false
	}

}

// Configures a New scan and returns the location
func ScanConfig(target, port, urls, username, password, apikey string) (ScanLocation string) {
	var endpoint string
	if apikey != "" {
		endpoint = "http://" + target + ":" + port + "/" + apikey + "/v0.1/scan"
	} else {
		endpoint = "http://" + target + ":" + port + "/v0.1/scan"
	}
	var url_string string
	// At the moment, this only allows 1 url to be scanned
	if username == "" && password == "" {
		fmt.Fprintf(color.Output, " %v Setting up scanner...\n", cyan("[i] INFO"))
		url_string = `{"urls":["` + urls + `"]}`
	} else {
		fmt.Fprintf(color.Output, " %v Setting up scanner using credentials %v:%v\n", cyan("[i] INFO"), username, password)
		url_string = `{"application_logins":[{"password":"` + password + `","username":"` + username + `"}],"urls":["` + urls + `"]}`
	}
	var body = []byte(url_string)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		fmt.Println("Error")
	}

	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("Error")
	}
	Location := resp.Header.Get("Location")
	defer resp.Body.Close()

	//if resp.StatusCode != 201 {
	//fmt.Println("Error")
	//}

	return Location
}

// Get issue description from Burp's database
func GetDescription(target, port, issueName, apikey string) {
	var endpoint string
	if apikey != "" {
		endpoint = "http://" + target + ":" + port + "/" + apikey + "/v0.1/knowledge_base/issue_definitions"
	} else {
		endpoint = "http://" + target + ":" + port + "/v0.1/knowledge_base/issue_definitions"
	}

	resp, err := client.Get(endpoint)

	if err != nil {
		fmt.Fprintf(color.Output, "%v Can't perform request to %v.\n", red(" [-] ERROR:"), endpoint)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(color.Output, "%v Resource not found.\n", red(" [-] ERROR:"))
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(color.Output, "%v Fetching '%v' information...\n", cyan(" [i] INFO:"), issueName)
		raw_issues := string(body)[1 : len(string(body))-1]
		var descriptionSelected string = `..#[name="` + issueName + `"]`
		value := gjson.Get(raw_issues, descriptionSelected)

		description := gjson.Get(value.String(), "description")
		desc_stripped := strip.StripTags(description.String())
		remediation := gjson.Get(value.String(), "remediation")
		rem_stripped := strip.StripTags(remediation.String())

		fmt.Fprintf(color.Output, "\t %v %v\n", cyanBG(" [*] DESCRIPTION:"), desc_stripped)
		fmt.Fprintf(color.Output, "\t %v %v\n", greenBG(" [*] REMEDIATION:"), rem_stripped)
	}

}

// CheckScanStatus checks the status of a scan
func CheckScanStatus(target, port, scanID, apikey string) (status string, err error) {
	var endpoint string
	if apikey != "" {
		endpoint = "http://" + target + ":" + port + "/" + apikey + "/v0.1/scan/" + scanID
	} else {
		endpoint = "http://" + target + ":" + port + "/v0.1/scan/" + scanID
	}

	resp, err := client.Get(endpoint)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("scan ID not found")
	}

	body, _ := ioutil.ReadAll(resp.Body)
	status = gjson.Get(string(body), "scan_status").String()
	return status, nil
}

// ScanConfigAdvanced configures a new scan with advanced options including OpenAPI compliance features
func ScanConfigAdvanced(target, port, urls, username, password, apikey, scanConfig, scopeInclude, scopeExclude, protocolOption, customConfigFile, burpConfigName string, configNumber int, scanName, resourcePool, callbackURL string, advancedScope bool, recordedLoginScript string) (ScanLocation string) {
	var endpoint string
	if apikey != "" {
		endpoint = "http://" + target + ":" + port + "/" + apikey + "/v0.1/scan"
	} else {
		endpoint = "http://" + target + ":" + port + "/v0.1/scan"
	}

	// Build scan request JSON
	scanRequest := make(map[string]interface{})
	
	// URLs array
	scanRequest["urls"] = []string{urls}
	
	// v1.1.7: Scan name support
	if scanName != "" {
		scanRequest["name"] = scanName
		fmt.Fprintf(color.Output, " %v Scan name: %v\n", cyan("[i] INFO"), scanName)
	}
	
	// Application logins - support both username/password and recorded login scripts
	var logins []map[string]interface{}
	
	// v1.1.7: Recorded login script support
	if recordedLoginScript != "" {
		scriptData, err := ioutil.ReadFile(recordedLoginScript)
		if err != nil {
			fmt.Fprintf(color.Output, "%v Error reading recorded login script %v: %v\n", red(" [-] ERROR:"), recordedLoginScript, err)
			return ""
		}
		
		logins = append(logins, map[string]interface{}{
			"type":   "RecordedLogin",
			"label":  "Recorded Login",
			"script": string(scriptData),
		})
		fmt.Fprintf(color.Output, " %v Using recorded login script: %v\n", cyan("[i] INFO"), recordedLoginScript)
	}
	
	// Username/password login
	if username != "" && password != "" {
		logins = append(logins, map[string]interface{}{
			"type":     "UsernameAndPasswordLogin",
			"username": username,
			"password": password,
		})
		fmt.Fprintf(color.Output, " %v Using credentials: %v:%v\n", cyan("[i] INFO"), username, password)
	}
	
	if len(logins) > 0 {
		scanRequest["application_logins"] = logins
	} else {
		fmt.Fprintf(color.Output, " %v Setting up scanner...\n", cyan("[i] INFO"))
	}
	
	// Scan configurations - support numbered shortcuts, named and custom configurations
	var configs []map[string]interface{}
	
	// Configuration number shortcut (v1.1.6) - highest priority
	if configNumber > 0 {
		configItem, err := FindConfigByNumber(configNumber)
		if err != nil {
			fmt.Fprintf(color.Output, "%v %v\n", red(" [-] ERROR:"), err)
			return ""
		}
		
		switch configItem.Type {
		case "builtin":
			configs = append(configs, map[string]interface{}{
				"type": "NamedConfiguration",
				"name": configItem.Name,
			})
			fmt.Fprintf(color.Output, " %v Using built-in configuration #%v: %v\n", cyan("[i] INFO"), configNumber, configItem.Name)
		case "burp", "custom":
			configData, err := ioutil.ReadFile(configItem.Path)
			if err != nil {
				fmt.Fprintf(color.Output, "%v Error reading config file %v: %v\n", red(" [-] ERROR:"), configItem.Path, err)
				return ""
			}
			configs = append(configs, map[string]interface{}{
				"type":   "CustomConfiguration",
				"config": string(configData),
			})
			fmt.Fprintf(color.Output, " %v Using %v configuration #%v: %v (%v)\n", cyan("[i] INFO"), configItem.Type, configNumber, configItem.Name, configItem.Path)
		}
	} else {
		// Burp ConfigLibrary configuration (v1.1.5)
		if burpConfigName != "" {
			configFile, err := FindBurpConfigByName(burpConfigName)
			if err != nil {
				fmt.Fprintf(color.Output, "%v Error finding Burp config '%v': %v\n", red(" [-] ERROR:"), burpConfigName, err)
				return ""
			}
			
			configData, err := ioutil.ReadFile(configFile)
			if err != nil {
				fmt.Fprintf(color.Output, "%v Error reading Burp config file %v: %v\n", red(" [-] ERROR:"), configFile, err)
				return ""
			}
			
			configs = append(configs, map[string]interface{}{
				"type":   "CustomConfiguration",
				"config": string(configData),
			})
			fmt.Fprintf(color.Output, " %v Using Burp ConfigLibrary configuration: %v (%v)\n", cyan("[i] INFO"), burpConfigName, configFile)
		}
		
		// Custom configuration file (v1.1.4)
		if customConfigFile != "" {
			configData, err := ioutil.ReadFile(customConfigFile)
			if err != nil {
				fmt.Fprintf(color.Output, "%v Error reading config file %v: %v\n", red(" [-] ERROR:"), customConfigFile, err)
				return ""
			}
			
			configs = append(configs, map[string]interface{}{
				"type":   "CustomConfiguration",
				"config": string(configData),
			})
			fmt.Fprintf(color.Output, " %v Using custom configuration file: %v\n", cyan("[i] INFO"), customConfigFile)
		}
		
		// Named configuration
		if scanConfig != "" {
			configs = append(configs, map[string]interface{}{
				"type": "NamedConfiguration",
				"name": scanConfig,
			})
			fmt.Fprintf(color.Output, " %v Using scan configuration: %v\n", cyan("[i] INFO"), scanConfig)
		}
	}
	
	if len(configs) > 0 {
		scanRequest["scan_configurations"] = configs
	}
	
	// Scope configuration - support both simple and advanced scope
	if scopeInclude != "" || scopeExclude != "" {
		scope := make(map[string]interface{})
		
		// v1.1.7: Advanced scope support
		if advancedScope {
			scope["type"] = "AdvancedScope"
			fmt.Fprintf(color.Output, " %v Using advanced scope configuration\n", cyan("[i] INFO"))
			
			if scopeInclude != "" {
				includes := strings.Split(scopeInclude, ",")
				var includeRules []map[string]interface{}
				for _, rule := range includes {
					rule = strings.TrimSpace(rule)
					if rule != "" {
						// Parse advanced scope rule (protocol://host:port/path)
						advRule := parseAdvancedScopeRule(rule)
						includeRules = append(includeRules, advRule)
					}
				}
				if len(includeRules) > 0 {
					scope["include"] = includeRules
					fmt.Fprintf(color.Output, " %v Advanced scope include: %v rules\n", cyan("[i] INFO"), len(includeRules))
				}
			}
			
			if scopeExclude != "" {
				excludes := strings.Split(scopeExclude, ",")
				var excludeRules []map[string]interface{}
				for _, rule := range excludes {
					rule = strings.TrimSpace(rule)
					if rule != "" {
						advRule := parseAdvancedScopeRule(rule)
						excludeRules = append(excludeRules, advRule)
					}
				}
				if len(excludeRules) > 0 {
					scope["exclude"] = excludeRules
					fmt.Fprintf(color.Output, " %v Advanced scope exclude: %v rules\n", cyan("[i] INFO"), len(excludeRules))
				}
			}
		} else {
			// Simple scope (existing functionality)
			scope["type"] = "SimpleScope"
			
			if scopeInclude != "" {
				includes := strings.Split(scopeInclude, ",")
				var includeRules []map[string]string
				for _, rule := range includes {
					rule = strings.TrimSpace(rule)
					if rule != "" {
						includeRules = append(includeRules, map[string]string{"rule": rule})
					}
				}
				if len(includeRules) > 0 {
					scope["include"] = includeRules
					fmt.Fprintf(color.Output, " %v Simple scope include: %v\n", cyan("[i] INFO"), scopeInclude)
				}
			}
			
			if scopeExclude != "" {
				excludes := strings.Split(scopeExclude, ",")
				var excludeRules []map[string]string
				for _, rule := range excludes {
					rule = strings.TrimSpace(rule)
					if rule != "" {
						excludeRules = append(excludeRules, map[string]string{"rule": rule})
					}
				}
				if len(excludeRules) > 0 {
					scope["exclude"] = excludeRules
					fmt.Fprintf(color.Output, " %v Simple scope exclude: %v\n", cyan("[i] INFO"), scopeExclude)
				}
			}
		}
		
		scanRequest["scope"] = scope
	}
	
	// Protocol option
	if protocolOption != "" {
		if protocolOption == "httpAndHttps" || protocolOption == "specified" {
			scanRequest["protocol_option"] = protocolOption
			fmt.Fprintf(color.Output, " %v Protocol option: %v\n", cyan("[i] INFO"), protocolOption)
		} else {
			fmt.Fprintf(color.Output, " %v Invalid protocol option: %v, using default\n", yellow("[!] WARNING"), protocolOption)
		}
	}
	
	// v1.1.7: Resource pool support
	if resourcePool != "" {
		scanRequest["resource_pool"] = resourcePool
		fmt.Fprintf(color.Output, " %v Resource pool: %v\n", cyan("[i] INFO"), resourcePool)
	}
	
	// v1.1.7: Callback URL support
	if callbackURL != "" {
		callback := map[string]interface{}{
			"url": callbackURL,
		}
		scanRequest["scan_callback"] = callback
		fmt.Fprintf(color.Output, " %v Callback URL: %v\n", cyan("[i] INFO"), callbackURL)
	}
	
	// Convert to JSON
	jsonData, err := json.Marshal(scanRequest)
	if err != nil {
		fmt.Fprintf(color.Output, "%v Error creating scan request: %v\n", red(" [-] ERROR:"), err)
		return ""
	}
	
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		fmt.Fprintf(color.Output, "%v Error creating request: %v\n", red(" [-] ERROR:"), err)
		return ""
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(color.Output, "%v Error sending request: %v\n", red(" [-] ERROR:"), err)
		return ""
	}
	
	Location := resp.Header.Get("Location")
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(color.Output, "%v Scan creation failed (Status: %v): %v\n", red(" [-] ERROR:"), resp.StatusCode, string(body))
		return ""
	}

	return Location
}

// getBurpConfigLibraryPath returns the Burp Suite ConfigLibrary path for the current OS and user
func getBurpConfigLibraryPath() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %v", err)
	}
	
	username := currentUser.Username
	homeDir := currentUser.HomeDir
	
	var configPath string
	
	switch runtime.GOOS {
	case "windows":
		// Windows: C:\Users\$username\AppData\Roaming\BurpSuite\ConfigLibrary
		configPath = filepath.Join("C:", "Users", username, "AppData", "Roaming", "BurpSuite", "ConfigLibrary")
	case "darwin":
		// macOS: /Users/$username/.BurpSuite/ConfigLibrary
		configPath = filepath.Join(homeDir, ".BurpSuite", "ConfigLibrary")
	case "linux":
		// Linux: Check if root user or normal user
		if username == "root" {
			configPath = filepath.Join("/root", ".BurpSuite", "ConfigLibrary")
		} else {
			configPath = filepath.Join(homeDir, ".BurpSuite", "ConfigLibrary")
		}
	default:
		return "", fmt.Errorf("unsupported operating system: %v", runtime.GOOS)
	}
	
	return configPath, nil
}

// ListBurpConfigLibrary scans Burp Suite's official ConfigLibrary directory
func ListBurpConfigLibrary() []string {
	fmt.Fprintf(color.Output, "\n%v Scanning Burp Suite ConfigLibrary:\n", yellowBG(" [*] BURP CONFIGS:"))
	
	configPath, err := getBurpConfigLibraryPath()
	if err != nil {
		fmt.Fprintf(color.Output, "\t %v Error getting ConfigLibrary path: %v\n", red("[-] ERROR:"), err)
		return []string{}
	}
	
	fmt.Fprintf(color.Output, "\t %v Checking: %v\n", cyan("[i] INFO:"), configPath)
	
	// Check if ConfigLibrary directory exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Fprintf(color.Output, "\t %v Burp Suite ConfigLibrary not found\n", yellow("[!] WARNING:"))
		fmt.Fprintf(color.Output, "\t %v Make sure Burp Suite Professional is installed\n", cyan("[i] INFO:"))
		return []string{}
	}
	
	// Scan for JSON files in ConfigLibrary
	files, err := filepath.Glob(filepath.Join(configPath, "*.json"))
	if err != nil {
		fmt.Fprintf(color.Output, "\t %v Error scanning ConfigLibrary: %v\n", red("[-] ERROR:"), err)
		return []string{}
	}
	
	var validConfigs []string
	
	if len(files) > 0 {
		fmt.Fprintf(color.Output, "\t %v Found Burp Suite configurations:\n", green("[+] SUCCESS:"))
		for i, file := range files {
			// Get just the filename without extension for display
			filename := filepath.Base(file)
			configName := strings.TrimSuffix(filename, filepath.Ext(filename))
			
			fmt.Fprintf(color.Output, "\t %v %v (%v)\n", cyanBG("["+strconv.Itoa(i+1)+"]"), configName, file)
			validConfigs = append(validConfigs, file)
		}
		fmt.Fprintf(color.Output, "\n\t %v Usage: ./burp-cli -s \"https://example.com\" -cf \"%v\"\n", cyan("[i] INFO:"), files[0])
	} else {
		fmt.Fprintf(color.Output, "\t %v No configuration files found in ConfigLibrary\n", yellow("[!] WARNING:"))
		fmt.Fprintf(color.Output, "\t %v Create and save configurations in Burp Suite first\n", cyan("[i] INFO:"))
	}
	
	return validConfigs
}

// ListCustomConfigFiles scans for custom configuration files in common directories
func ListCustomConfigFiles() []string {
	fmt.Fprintf(color.Output, "\n%v Scanning for Custom Configuration Files:\n", yellowBG(" [*] CUSTOM FILES:"))
	
	// Common directories where users might store config files
	searchDirs := []string{
		".",
		"./configs",
		"./burp-configs", 
		"~/.burp",
		"~/burp-configs",
	}
	
	foundFiles := []string{}
	
	for _, dir := range searchDirs {
		// Expand home directory
		if strings.HasPrefix(dir, "~/") {
			homeDir, err := os.UserHomeDir()
			if err == nil {
				dir = strings.Replace(dir, "~", homeDir, 1)
			}
		}
		
		// Check if directory exists
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		
		// Look for JSON files
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			continue
		}
		
		for _, file := range files {
			// Check if it looks like a Burp config file
			if isLikelyBurpConfig(file) {
				foundFiles = append(foundFiles, file)
			}
		}
	}
	
	if len(foundFiles) > 0 {
		fmt.Fprintf(color.Output, "\t %v Found potential configuration files:\n", green("[+] SUCCESS:"))
		for i, file := range foundFiles {
			fmt.Fprintf(color.Output, "\t %v %v\n", cyanBG("["+strconv.Itoa(i+1)+"]"), file)
		}
		fmt.Fprintf(color.Output, "\n\t %v Usage: ./burp-cli -s \"https://example.com\" -cf \"path/to/config.json\"\n", cyan("[i] INFO:"))
	} else {
		fmt.Fprintf(color.Output, "\t %v No custom configuration files found in common directories\n", yellow("[!] WARNING:"))
		fmt.Fprintf(color.Output, "\t %v Export configurations from Burp Suite to use this feature\n", cyan("[i] INFO:"))
	}
	
	return foundFiles
}

// FindBurpConfigByName finds a configuration file in Burp's ConfigLibrary by name
func FindBurpConfigByName(configName string) (string, error) {
	configPath, err := getBurpConfigLibraryPath()
	if err != nil {
		return "", err
	}
	
	// Check if ConfigLibrary directory exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return "", fmt.Errorf("Burp Suite ConfigLibrary not found at: %v", configPath)
	}
	
	// Look for the configuration file
	// Try with .json extension
	configFile := filepath.Join(configPath, configName+".json")
	if _, err := os.Stat(configFile); err == nil {
		return configFile, nil
	}
	
	// Try without extension (in case user provided .json)
	if strings.HasSuffix(configName, ".json") {
		configName = strings.TrimSuffix(configName, ".json")
		configFile = filepath.Join(configPath, configName+".json")
		if _, err := os.Stat(configFile); err == nil {
			return configFile, nil
		}
	}
	
	// If exact match not found, try case-insensitive search
	files, err := filepath.Glob(filepath.Join(configPath, "*.json"))
	if err != nil {
		return "", fmt.Errorf("error scanning ConfigLibrary: %v", err)
	}
	
	for _, file := range files {
		filename := filepath.Base(file)
		name := strings.TrimSuffix(filename, filepath.Ext(filename))
		if strings.EqualFold(name, configName) {
			return file, nil
		}
	}
	
	return "", fmt.Errorf("configuration '%v' not found in Burp ConfigLibrary", configName)
}

// parseAdvancedScopeRule parses a URL-like rule into advanced scope format
func parseAdvancedScopeRule(rule string) map[string]interface{} {
	advRule := map[string]interface{}{
		"protocol": "any", // default
	}
	
	// Try to parse as URL
	if strings.Contains(rule, "://") {
		if u, err := url.Parse(rule); err == nil {
			// Set protocol
			if u.Scheme == "http" {
				advRule["protocol"] = "http"
			} else if u.Scheme == "https" {
				advRule["protocol"] = "https"
			}
			
			// Set host
			if u.Host != "" {
				if u.Port() != "" {
					advRule["host_or_ip_range"] = u.Hostname()
					advRule["port"] = u.Port()
				} else {
					advRule["host_or_ip_range"] = u.Host
				}
			}
			
			// Set file/path
			if u.Path != "" && u.Path != "/" {
				advRule["file"] = u.Path
			}
		}
	} else {
		// Simple rule, treat as host pattern
		advRule["host_or_ip_range"] = rule
	}
	
	return advRule
}

// isLikelyBurpConfig checks if a JSON file looks like a Burp configuration
func isLikelyBurpConfig(filename string) bool {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return false
	}
	
	content := string(data)
	// Look for common Burp configuration indicators
	indicators := []string{
		"scan_configuration",
		"crawl_strategy", 
		"audit_strategy",
		"burp_configuration",
		"scanner_config",
	}
	
	for _, indicator := range indicators {
		if strings.Contains(strings.ToLower(content), indicator) {
			return true
		}
	}
	
	return false
}

// ConfigItem represents a configuration item with its details
type ConfigItem struct {
	Name        string
	Path        string
	Type        string // "builtin", "burp", "custom"
	Description string
}

// GetAllConfigurations returns all available configurations in order
func GetAllConfigurations() []ConfigItem {
	var allConfigs []ConfigItem
	
	// 1. Built-in configurations (shown first)
	builtinConfigs := []ConfigItem{
		{"Crawl and Audit - Fast", "", "builtin", "Quick scan with basic checks"},
		{"Crawl and Audit - Balanced", "", "builtin", "Medium depth with good coverage"},
		{"Crawl and Audit - Deep", "", "builtin", "Thorough scan with extensive checks"},
		{"Audit only - Fast", "", "builtin", "Quick security testing without crawling"},
		{"Audit only - Balanced", "", "builtin", "Medium depth security testing"},
		{"Audit only - Deep", "", "builtin", "Thorough security testing"},
		{"Crawl only", "", "builtin", "Only discovers content, no security testing"},
		{"Crawl and Audit - Lightweight", "", "builtin", "Minimal resource usage"},
		{"Audit only - Lightweight", "", "builtin", "Lightweight security testing"},
		{"Crawl and Audit - Maximum", "", "builtin", "Most comprehensive scan"},
		{"Audit only - Maximum", "", "builtin", "Maximum security testing"},
		{"Never stop crawling due to application errors", "", "builtin", "Persistent crawling"},
		{"Never stop audit due to application errors", "", "builtin", "Persistent auditing"},
		{"Minimize false negatives", "", "builtin", "Comprehensive testing approach"},
		{"Minimize false positives", "", "builtin", "Conservative testing approach"},
	}
	allConfigs = append(allConfigs, builtinConfigs...)
	
	// 2. Burp ConfigLibrary configurations
	configPath, err := getBurpConfigLibraryPath()
	if err == nil {
		if _, err := os.Stat(configPath); err == nil {
			files, err := filepath.Glob(filepath.Join(configPath, "*.json"))
			if err == nil {
				for _, file := range files {
					filename := filepath.Base(file)
					configName := strings.TrimSuffix(filename, filepath.Ext(filename))
					allConfigs = append(allConfigs, ConfigItem{
						Name: configName,
						Path: file,
						Type: "burp",
						Description: "Burp Suite ConfigLibrary",
					})
				}
			}
		}
	}
	
	// 3. Custom configuration files
	searchDirs := []string{".", "./configs", "./burp-configs"}
	for _, dir := range searchDirs {
		if _, err := os.Stat(dir); err == nil {
			files, err := filepath.Glob(filepath.Join(dir, "*.json"))
			if err == nil {
				for _, file := range files {
					if isLikelyBurpConfig(file) {
						filename := filepath.Base(file)
						configName := strings.TrimSuffix(filename, filepath.Ext(filename))
						allConfigs = append(allConfigs, ConfigItem{
							Name: configName,
							Path: file,
							Type: "custom",
							Description: "Custom configuration file",
						})
					}
				}
			}
		}
	}
	
	return allConfigs
}

// FindConfigByNumber finds a configuration by its number from the list
func FindConfigByNumber(number int) (ConfigItem, error) {
	configs := GetAllConfigurations()
	if number < 1 || number > len(configs) {
		return ConfigItem{}, fmt.Errorf("invalid configuration number: %d (valid range: 1-%d)", number, len(configs))
	}
	return configs[number-1], nil
}

// ListScanConfigurations lists available scan configurations with improved order and numbering
func ListScanConfigurations(target, port, apikey string) {
	fmt.Fprintf(color.Output, "%v Available Scan Configurations:\n", cyan(" [i] INFO:"))
	
	// Try to get configurations from Burp (this might not be available in all versions)
	fmt.Fprintf(color.Output, "\n%v Checking Burp for available configurations...\n", cyan(" [i] INFO:"))
	
	// First check if Burp is accessible
	if !CheckBurp(target, port, apikey) {
		fmt.Fprintf(color.Output, "%v Burp API not accessible, showing available configurations\n", red(" [-] ERROR:"))
	} else {
		fmt.Fprintf(color.Output, "%v Burp API accessible\n", green(" [+] SUCCESS:"))
	}
	
	// Get all configurations
	allConfigs := GetAllConfigurations()
	
	// v1.1.6: Display configurations in improved order with numbering
	fmt.Fprintf(color.Output, "\n%v Built-in Configurations:\n", yellowBG(" [*] BUILT-IN:"))
	builtinCount := 0
	for i, config := range allConfigs {
		if config.Type == "builtin" {
			builtinCount++
			fmt.Fprintf(color.Output, "\t %v %v - %v\n", cyanBG("["+strconv.Itoa(i+1)+"]"), config.Name, config.Description)
		}
	}
	
	// v1.1.6: Display Burp ConfigLibrary configurations
	fmt.Fprintf(color.Output, "\n%v Burp Suite ConfigLibrary:\n", yellowBG(" [*] BURP CONFIGS:"))
	burpCount := 0
	for i, config := range allConfigs {
		if config.Type == "burp" {
			burpCount++
			fmt.Fprintf(color.Output, "\t %v %v (%v)\n", cyanBG("["+strconv.Itoa(i+1)+"]"), config.Name, config.Path)
		}
	}
	if burpCount == 0 {
		configPath, _ := getBurpConfigLibraryPath()
		fmt.Fprintf(color.Output, "\t %v No configurations found in: %v\n", yellow("[!] WARNING:"), configPath)
		fmt.Fprintf(color.Output, "\t %v Create and save configurations in Burp Suite first\n", cyan("[i] INFO:"))
	}
	
	// v1.1.6: Display custom configurations
	fmt.Fprintf(color.Output, "\n%v Custom Configuration Files:\n", yellowBG(" [*] CUSTOM FILES:"))
	customCount := 0
	for i, config := range allConfigs {
		if config.Type == "custom" {
			customCount++
			fmt.Fprintf(color.Output, "\t %v %v (%v)\n", cyanBG("["+strconv.Itoa(i+1)+"]"), config.Name, config.Path)
		}
	}
	if customCount == 0 {
		fmt.Fprintf(color.Output, "\t %v No custom configuration files found\n", yellow("[!] WARNING:"))
		fmt.Fprintf(color.Output, "\t %v Export configurations from Burp Suite to use this feature\n", cyan("[i] INFO:"))
	}
	
	// v1.1.6: Show summary with numbered shortcuts
	fmt.Fprintf(color.Output, "\n%v Total configurations: %v\n", green(" [+] SUMMARY:"), len(allConfigs))
	fmt.Fprintf(color.Output, "\t • Built-in: %v\n", builtinCount)
	fmt.Fprintf(color.Output, "\t • Burp ConfigLibrary: %v\n", burpCount)
	fmt.Fprintf(color.Output, "\t • Custom files: %v\n", customCount)
	
	fmt.Fprintf(color.Output, "\n%v Built-in Configurations:\n", yellowBG(" [*] BUILT-IN:"))
	
	// Common built-in configurations based on Burp Suite documentation
	builtinConfigs := []string{
		"Crawl and Audit - Fast",
		"Crawl and Audit - Balanced", 
		"Crawl and Audit - Deep",
		"Audit only - Fast",
		"Audit only - Balanced",
		"Audit only - Deep",
		"Crawl only",
		"Crawl and Audit - Lightweight",
		"Audit only - Lightweight",
		"Crawl and Audit - Maximum",
		"Audit only - Maximum",
		"Never stop crawling due to application errors",
		"Never stop audit due to application errors",
		"Minimize false negatives",
		"Minimize false positives",
	}
	
	for i, config := range builtinConfigs {
		fmt.Fprintf(color.Output, "\t %v %v\n", cyanBG("["+strconv.Itoa(i+1)+"]"), config)
	}
	
	fmt.Fprintf(color.Output, "\n%v Usage Examples:\n", greenBG(" [*] EXAMPLES:"))
	fmt.Fprintf(color.Output, "\t # Use configuration by number (FASTEST)\n")
	fmt.Fprintf(color.Output, "\t ./burp-cli -s \"https://example.com\" -cn 1\n")
	fmt.Fprintf(color.Output, "\t ./burp-cli -s \"https://example.com\" -cn 3 -a\n")
	fmt.Fprintf(color.Output, "\t # Use by name\n")
	fmt.Fprintf(color.Output, "\t ./burp-cli -s \"https://example.com\" -sc \"Crawl and Audit - Fast\"\n")
	fmt.Fprintf(color.Output, "\t ./burp-cli -s \"https://example.com\" -bc \"SQL\"\n")
	
	fmt.Fprintf(color.Output, "\n%v Configuration Details:\n", yellowBG(" [*] DETAILS:"))
	fmt.Fprintf(color.Output, "\t • Fast: Quick scan with basic checks\n")
	fmt.Fprintf(color.Output, "\t • Balanced: Medium depth with good coverage\n") 
	fmt.Fprintf(color.Output, "\t • Deep: Thorough scan with extensive checks\n")
	fmt.Fprintf(color.Output, "\t • Lightweight: Minimal resource usage\n")
	fmt.Fprintf(color.Output, "\t • Maximum: Most comprehensive scan\n")
	fmt.Fprintf(color.Output, "\t • Crawl only: Only discovers content, no security testing\n")
	fmt.Fprintf(color.Output, "\t • Audit only: Security testing without crawling\n")
	
	fmt.Fprintf(color.Output, "\n%v How to Find Your Custom Configurations:\n", yellowBG(" [*] CUSTOM:"))
	fmt.Fprintf(color.Output, "\t 1. Open Burp Suite Professional\n")
	fmt.Fprintf(color.Output, "\t 2. Go to 'Scanner' > 'Scan configurations'\n")
	fmt.Fprintf(color.Output, "\t 3. Look at the 'Name' column for available configurations\n")
	fmt.Fprintf(color.Output, "\t 4. Use the exact name (case-sensitive) with -sc parameter\n")
	
	fmt.Fprintf(color.Output, "\n%v Alternative Method:\n", yellowBG(" [*] ALTERNATIVE:"))
	fmt.Fprintf(color.Output, "\t You can also export configurations from Burp Suite:\n")
	fmt.Fprintf(color.Output, "\t 1. In Burp Suite: Scanner > Scan configurations > Select config > Export\n")
	fmt.Fprintf(color.Output, "\t 2. Save as JSON file\n")
	fmt.Fprintf(color.Output, "\t 3. Use the configuration name from the exported JSON\n")
}

// Get Issue Names from Burp Database
func GetNames(target, port, apikey string) {
	var endpoint string
	if apikey != "" {
		endpoint = "http://" + target + ":" + port + "/" + apikey + "/v0.1/knowledge_base/issue_definitions"
	} else {
		endpoint = "http://" + target + ":" + port + "/v0.1/knowledge_base/issue_definitions"
	}

	resp, err := client.Get(endpoint)

	if err != nil {
		fmt.Fprintf(color.Output, "%v Can't perform request to %v.\n", red(" [-] ERROR:"), endpoint)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(color.Output, "%v Resource not found.\n", red(" [-] ERROR:"))
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(color.Output, "%v Retrieving vulnerability names...\n", cyan(" [i] INFO:"))
		raw_issues := string(body)[1 : len(string(body))-1]

		value := gjson.Get(raw_issues, "..#.name")

		var VulnNames []string
		for k, vulnName := range value.Array() {
			VulnNames = append(VulnNames, vulnName.String())
			fmt.Fprintf(color.Output, "\t %v %v\n", cyanBG("["+strconv.Itoa(k+1)+"]"), vulnName.String())
		}
	}
}
