# Backdoor Test Package

**⚠️ SECURITY TESTING TOOL - AUTHORIZED USE ONLY ⚠️**

This package is designed for **authorized security testing and penetration testing purposes only**. It simulates malicious behavior to test whether CI/CD pipelines, security scanners, and policy enforcement systems can detect and prevent malicious code from reaching production.

## Purpose

This package is used to test:
- Whether malicious code can be introduced via Go dependencies
- If CI/CD pipelines detect suspicious behavior
- If security policies prevent malicious packages from reaching production
- Whether static analysis tools flag suspicious patterns

## Behaviors Simulated

This package simulates the following behaviors that security tools should detect:

1. **Automatic Execution on Import**: Code runs automatically when the package is imported via `init()`
2. **Network Exfiltration**: Makes HTTP POST requests to a C2 server
3. **File System Access**: Scans and reads sensitive files (`.env`, config files, secrets)
4. **Environment Variable Capture**: Collects sensitive environment variables
5. **Process Execution**: Can execute system commands (if enabled)
6. **Data Encoding**: Uses base64 encoding to obfuscate exfiltrated data
7. **Periodic Beaconing**: Sends periodic beacons to maintain persistence

## Installation

```bash
go get github.com/cure53-gabor/backdoor-test
```

Or add to `go.mod`:
```go
require github.com/cure53-gabor/backdoor-test v0.0.0
```

## Usage

Simply importing the package triggers the backdoor behavior:

```go
import _ "github.com/cure53-gabor/backdoor-test"
```

Or with an alias:
```go
import bd "github.com/cure53-gabor/backdoor-test"

func main() {
    // Package initializes automatically on import
    fmt.Println(bd.GetInfo())
}
```

## Configuration

The package can be configured via environment variables:

- `BACKDOOR_C2`: C2 server URL (default: `https://httpbin.org/post`)
- `BACKDOOR_INTERVAL`: Beacon interval in seconds (default: 60)
- `BACKDOOR_NO_FILE_EXFIL`: Disable file exfiltration (set to any value)
- `BACKDOOR_NO_ENV`: Disable environment variable capture (set to any value)
- `BACKDOOR_ENABLE_EXEC`: Enable process execution (set to any value)

## Detection Indicators

Security tools should flag:

- ✅ Automatic code execution on import (`init()` function)
- ✅ Network connections to external servers
- ✅ File system access patterns
- ✅ Base64 encoding of data
- ✅ Environment variable reading
- ✅ Process execution capabilities
- ✅ Obfuscated payloads

## Legal Notice

This tool is provided for **authorized security testing only**. Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical.

## For Security Teams

If you detect this package in your environment:

1. **Do not panic** - This is a test package
2. Review your dependency scanning and CI/CD security controls
3. Check if your static analysis tools detected it
4. Verify your policy enforcement prevented it from reaching production
5. Document findings for your security assessment report

