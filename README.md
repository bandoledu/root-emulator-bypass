# Root Detection & SSL Bypass Script

This repository contains a comprehensive Frida script for bypassing root detection and SSL certificate pinning in Android applications.

## Technical Implementation

The script provides three main bypass functionalities:

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


## Features

The script includes extensive bypass capabilities:

### Root Detection
- Blocks checks for over 35 common root-related files
- Intercepts checks for over 25 root-related packages
- Prevents detection of common root binaries
- Modifies system properties to hide root status
- Caches results for improved performance

### SSL Pinning
- Implements custom TrustManager
- Bypasses multiple SSL validation mechanisms
- Handles certificate validation exceptions
- Supports various SSL implementations:
  - Default SSL
  - OkHttp
  - TrustKit
  - WebView


## Prerequisites

- Frida installed on your system
- Rooted Android device or emulator
- Burp Suite for SSL interception
- ADB (Android Debug Bridge)

## Setup Instructions

### 1. SSL Certificate Setup

1. Export Burp Suite's CA certificate:
   - Open Burp Suite
   - Go to `Proxy` -> `Options` -> `TLS`
   - Click on `Export CA certificate`
   - Choose `Certificate in DER format` 
   - Save it as `burp.crt`

   Alternative certificate formats and conversions:
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

2. Verify the certificate format:
   ```bash
   # Check certificate information
   openssl x509 -in burp.crt -inform DER -text -noout
   ```

3. Push the certificate to the device:
   ```bash
   adb push burp.crt /data/local/tmp/burp.crt
   adb shell "chmod 644 /data/local/tmp/burp.crt"
   ```

   Note: The certificate should be in DER format and have the following characteristics:
   - File extension: `.crt`
   - Format: X.509
   - Encoding: DER (binary)
   - Location on device: `/data/local/tmp/burp.crt`
   - Permissions: 644 (readable by all)

### 2. Frida Setup

1. Install Frida on your host machine:
   ```bash
   pip install frida-tools
   ```

2. Push frida-server to your device:
   ```bash
   # Download appropriate frida-server version from GitHub
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   ```

3. Start frida-server on device:
   ```bash
   adb shell "/data/local/tmp/frida-server &"
   ```

### 3. Running the Script

1. Save the script as `root_bypass.js`

2. Run the script with Frida:
   ```bash
   frida -U -l root_bypass.js -f com.target.application
   ```
   Replace `com.target.application` with your target app's package name.

## Security Notice

This tool is designed strictly for legitimate security research, penetration testing, and vulnerability assessment purposes. Using this tool to bypass root detection or SSL pinning without explicit authorization may violate applicable laws, terms of service, or privacy regulations. Security researchers should obtain proper permission before testing any application and respect responsible disclosure practices. The ability to bypass security controls carries significant ethical responsibilities. Never use this tool on applications or systems without proper authorization from the system owner. The authors of this tool are not responsible for any misuse or damage caused by using this bypass script. Always ensure compliance with relevant laws, regulations, and ethical guidelines when conducting security research. 

![Image](https://github.com/user-attachments/assets/8b7a0743-edf0-4c14-b5ad-f103d78a157d)