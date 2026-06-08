# Android Manifest Security Assessment Report

**Target APK:** AndroGoat (OWASP Security Testing App)  
**Package:** `owasp.sat.agoat`  
**Manifest Path:** `decoded/AndroidManifest.xml`  
**Network Config Path:** `decoded/res/xml/network_security_config.xml`  
**Assessment Type:** Static Analysis – AndroidManifest.xml Review

---

## Table of Contents

1. [Permissions Analysis](#1-permissions-analysis)
2. [Deep Link Analysis](#2-deep-link-analysis)
3. [Exported Components](#3-exported-components)
4. [Insecure Application Configurations](#4-insecure-application-configurations)
5. [Network Security Configuration](#5-network-security-configuration)
6. [Findings Summary Table](#6-findings-summary-table)
7. [Recommendations](#7-recommendations)

---

## 1. Permissions Analysis

**File:** `decoded/AndroidManifest.xml`

The application declares the following permissions:

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
```

| Permission | Purpose | Risk |
|---|---|---|
| `INTERNET` | Network communication | Low – commonly required |
| `READ_EXTERNAL_STORAGE` | Read files from shared storage | Medium – may access sensitive user files |
| `WRITE_EXTERNAL_STORAGE` | Write files to shared storage | Medium – data may be accessible to other apps |

**Notes:**  
Storage permissions (`READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`) grant access to shared external storage, which is readable by other applications on older Android versions (pre-Android 10). Verify whether these permissions are strictly required for the app's functionality.

---

## 2. Deep Link Analysis

### 2a. Understanding Deep Links and Intent Filters

A **deep link** allows external apps, browsers, or system components to navigate directly into a specific screen of the application using a URI scheme.

- **Standard Deep Links** – Use custom URI schemes (e.g., `myapp://path`). No domain verification is performed.
- **App Links** – Use `https://` scheme with domain verified via `assetlinks.json`. Stronger trust model.

**Security Implications:**

| Risk | Description |
|---|---|
| **Deep Link Hijacking** | Another app registers the same URI scheme and intercepts intents |
| **Open Redirects** | App blindly follows a URL passed via the deep link |
| **Unauthorized Access** | Sensitive activity exposed without authentication checks |

---

### 2b. Deep Link Found in AndroGoat

**File:** `decoded/AndroidManifest.xml` (lines 22–28)

```xml
<activity android:name="owasp.sat.agoat.AccessControl1ViewActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:host="vulnapp" android:scheme="androgoat"/>
    </intent-filter>
</activity>
```

**Deep Link URI:** `androgoat://vulnapp`

**Analysis:**

- The activity is reachable via the custom URI scheme `androgoat://vulnapp`.
- The `BROWSABLE` category is **not** present, meaning this link cannot be triggered directly from a web browser. However, it can be launched by other installed applications or via ADB.
- No authentication or authorization enforcement was observed in the manifest.
- The activity name (`AccessControl1ViewActivity`) suggests it may be related to an access control vulnerability.

**Dynamic Verification Command:**

```bash
adb shell am start \
  -a android.intent.action.VIEW \
  -d "androgoat://vulnapp"
```

**Expected Result:** `AccessControl1ViewActivity` launches without authentication.

---

## 3. Exported Components

Exported components are accessible to other apps on the device. Each must be reviewed to ensure no sensitive functionality is exposed unintentionally.

---

### Finding 1 – Exported Broadcast Receiver

**File:** `decoded/AndroidManifest.xml`

```xml
<receiver
    android:name="owasp.sat.agoat.ShowDataReceiver"
    android:enabled="true"
    android:exported="true"/>
```

| Field | Detail |
|---|---|
| **Component** | `owasp.sat.agoat.ShowDataReceiver` |
| **Type** | Broadcast Receiver |
| **Exported** | `true` |
| **Risk** | External applications can send arbitrary broadcasts to this receiver |
| **Impact** | May trigger unintended behavior or expose internal data if input is not validated |
| **Recommendation** | Set `android:exported="false"` if external access is not required; validate all incoming intents |

---

### Finding 2 – Exported Service

**File:** `decoded/AndroidManifest.xml`

```xml
<service
    android:name="owasp.sat.agoat.DownloadInvoiceService"
    android:enabled="true"
    android:exported="true"/>
```

| Field | Detail |
|---|---|
| **Component** | `owasp.sat.agoat.DownloadInvoiceService` |
| **Type** | Service |
| **Exported** | `true` |
| **Risk** | External applications may start or bind to this service |
| **Impact** | Unauthorized invocation of internal functionality (e.g., invoice download) |
| **Recommendation** | Set `android:exported="false"` or enforce `android:permission` to restrict access |

---

## 4. Insecure Application Configurations

---

### Finding 3 – Debuggable Flag Enabled

**File:** `decoded/AndroidManifest.xml`

```xml
<application
    android:debuggable="true"
    ...>
```

| Field | Detail |
|---|---|
| **Attribute** | `android:debuggable` |
| **Current Value** | `true` |
| **Risk** | Allows runtime debugging via ADB on non-rooted devices |
| **Impact** | An attacker can attach a debugger, inspect memory, intercept method calls, and extract sensitive data |
| **Recommendation** | Set `android:debuggable="false"` in all production builds |

**Fix:**
```xml
<application android:debuggable="false" ...>
```

---

### Finding 4 – allowBackup Enabled

**File:** `decoded/AndroidManifest.xml`

```xml
<application
    android:allowBackup="true"
    ...>
```

| Field | Detail |
|---|---|
| **Attribute** | `android:allowBackup` |
| **Current Value** | `true` |
| **Risk** | Application data is included in ADB and cloud backups |
| **Impact** | Sensitive data (shared preferences, databases, tokens) can be extracted from a backup without root access |
| **Recommendation** | Set `android:allowBackup="false"` if backups are not required |

**Extraction Example (attacker perspective):**
```bash
adb backup -noapk owasp.sat.agoat
```

**Fix:**
```xml
<application android:allowBackup="false" ...>
```

---

## 5. Network Security Configuration

**File:** `decoded/res/xml/network_security_config.xml`  
**Referenced in Manifest:** `android:networkSecurityConfig="@xml/network_security_config"`

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```

---

### Finding 5 – Cleartext Traffic Permitted

| Field | Detail |
|---|---|
| **Attribute** | `cleartextTrafficPermitted` |
| **Current Value** | `true` |
| **Risk** | Application is allowed to send and receive data over unencrypted HTTP |
| **Impact** | Man-in-the-Middle (MITM) attacks, traffic interception, session hijacking, credential theft |
| **Recommendation** | Set `cleartextTrafficPermitted="false"` and enforce HTTPS for all connections |

**Fix:**
```xml
<base-config cleartextTrafficPermitted="false">
```

---

### Finding 6 – User-Installed Certificates Trusted

| Field | Detail |
|---|---|
| **Attribute** | `<certificates src="user"/>` |
| **Risk** | The app trusts certificates manually installed by the device user |
| **Impact** | An attacker who installs a malicious CA certificate on the device can intercept TLS traffic (SSL interception / MITM) |
| **Recommendation** | Remove `<certificates src="user"/>` in production builds; trust only the system store or pin specific certificates |

**Fix:**
```xml
<trust-anchors>
    <certificates src="system"/>
</trust-anchors>
```

---

## 6. Findings Summary Table

| # | Finding | Component / File | Severity |
|---|---|---|---|
| 1 | Exported Broadcast Receiver | `ShowDataReceiver` | Medium |
| 2 | Exported Service | `DownloadInvoiceService` | Medium |
| 3 | Debuggable Flag Enabled | `AndroidManifest.xml` – `<application>` | Medium |
| 4 | Backup Enabled (`allowBackup`) | `AndroidManifest.xml` – `<application>` | Medium |
| 5 | Cleartext Traffic Permitted | `network_security_config.xml` | High |
| 6 | User Certificates Trusted | `network_security_config.xml` | Medium |
| 7 | Unprotected Deep Link Handler | `AccessControl1ViewActivity` | Informational |

---

## 7. Recommendations

| # | Recommendation |
|---|---|
| 1 | Set `android:exported="false"` on `ShowDataReceiver` unless external broadcast access is required. Validate all incoming intents. |
| 2 | Set `android:exported="false"` on `DownloadInvoiceService` or restrict it with a custom permission. |
| 3 | Disable `android:debuggable` in all release/production builds. Use build variants to separate debug and release configurations. |
| 4 | Disable `android:allowBackup` or use `android:fullBackupContent` to explicitly exclude sensitive files. |
| 5 | Set `cleartextTrafficPermitted="false"` and ensure all endpoints use HTTPS. |
| 6 | Remove `<certificates src="user"/>` from production network security configuration. |
| 7 | Enforce authentication and authorization checks before processing any deep link intent in `AccessControl1ViewActivity`. |

---

## Useful Commands Reference

```bash
# Decode APK
apktool d app.apk

# Find all exported components
grep -R "exported" .

# Find all intent filters
grep -R "intent-filter" .

# Check backup setting
grep -R "allowBackup" .

# Check debug flag
grep -R "debuggable" .

# Test deep link via ADB
adb shell am start -a android.intent.action.VIEW -d "androgoat://vulnapp"

# Inspect exported receivers and services
adb shell dumpsys package owasp.sat.agoat | grep -A 5 receiver
adb shell dumpsys package owasp.sat.agoat | grep -A 5 service
```

---

*Report generated from static analysis of AndroGoat APK – OWASP Security Assessment Training Exercise.*
