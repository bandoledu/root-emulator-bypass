# Root Detection & SSL Bypass Script

A comprehensive Frida script for bypassing root detection and SSL certificate pinning in Android applications.

## Main Bypass Functionalities

### 1. SSL/Certificate Pinning Bypass
- Bypasses SSL certificate validation and pinning through multiple methods:
  - Custom X509TrustManager implementation
  - OkHttp CertificatePinner bypass
  - TrustKit pinning bypass
  - WebViewClient SSL error handler
  - Certificate pinning exception handling

### 2. Root Detection Bypass
- Comprehensive root detection bypass through:
  - Native file operation hooks (fopen, access)
  - System property checks
  - Shell command interception
  - Runtime.exec modifications
  - File existence checks
  - ProcessBuilder command filtering
  - Build property modifications
  - Package manager checks
  - BufferedReader modifications
  - Secure hardware attestation

### 3. Framework-Specific Bypasses
- IBM MobileFirst/WorkLight bypass
- Apache Cordova WebViewClient
- Appcelerator Titanium
- PhoneGap SSL checker
- Appmattus certificate transparency

## Technical Details

### Root Detection Features
- Blocks checks for over 35 common root-related files
- Intercepts checks for over 25 root-related packages
- Prevents detection of common root binaries
- Modifies system properties to hide root status
- Caches results for improved performance

### SSL Pinning Features
- Implements custom TrustManager
- Bypasses multiple SSL validation mechanisms
- Handles certificate validation exceptions
- Supports various SSL implementations:
  - Default SSL
  - OkHttp
  - TrustKit
  - WebView

## Setup Guide

### Prerequisites
- Frida installed on your system
- Rooted Android device or emulator
- Burp Suite for SSL interception
- ADB (Android Debug Bridge)

### SSL Certificate Setup

1. **Export Burp Suite Certificate:**
```bash
# Convert PEM to DER format
openssl x509 -in certificate.pem -outform DER -out burp.crt

# Convert CER to DER format
openssl x509 -in certificate.cer -outform DER -out burp.crt

# Convert P12 to DER format
openssl pkcs12 -in certificate.p12 -nodes -out temp.pem
openssl x509 -in temp.pem -outform DER -out burp.crt
rm temp.pem
```

2. **Verify Certificate:**
```bash
openssl x509 -in burp.crt -inform DER -text -noout
```

3. **Deploy Certificate:**
```bash
adb push burp.crt /data/local/tmp/burp.crt
adb shell "chmod 644 /data/local/tmp/burp.crt"
```

### Frida Setup

1. **Install Frida Tools:**
```bash
pip install frida-tools
```

2. **Deploy Frida Server:**
```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
```

3. **Start Frida Server:**
```bash
adb shell "/data/local/tmp/frida-server &"
```

### Running the Script

1. Save as `root_bypass.js`
2. Execute:
```bash
frida -U -l root_bypass.js -f com.target.application
```

## Security Notice

This tool is intended for:
- Legitimate security research
- Authorized penetration testing
- Vulnerability assessment

**Important:** 
- Obtain proper authorization before testing
- Respect responsible disclosure practices
- Comply with applicable laws and regulations
- Never use without explicit permission

The authors are not responsible for misuse or damage. Always ensure compliance with relevant laws and ethical guidelines.

## Additional Features

- Configurable logging system with multiple levels
- Selective bypass enabling/disabling
- Detailed error reporting
- Command whitelisting support
- Comprehensive security checks
- SELinux check bypasses
- Debug flag modifications
- ADB root detection bypass
- Custom security property handling
- Device fingerprint spoofing