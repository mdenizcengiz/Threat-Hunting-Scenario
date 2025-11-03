


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/mdenizcengiz/Threat-Hunting-Scenario/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "mdclabuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-01T22:27:19.7259964Z`. These events began at `2025-11-01T22:14:48.6065231Z`.

**Query used to locate events:**


<img width="1212" alt="image" src="https://github.com/mdenizcengiz/Threat-Hunting-Scenario/blob/main/Screenshots/1-DeviceFileEvents.png">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.exe". Based on the logs returned, at `2025-11-01T22:27:19.7259964Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-15.0.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**


<img width="1212" alt="image" src="https://github.com/mdenizcengiz/Threat-Hunting-Scenario/blob/main/Screenshots/2-DeviceProcessEvents.png">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-11-01T22:27:19.7259964Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

<img width="1212" alt="image" src="https://github.com/mdenizcengiz/Threat-Hunting-Scenario/blob/main/Screenshots/3-DeviceProcessEvents.png">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-11-01T22:24:53.8329239Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `66.70.211.20` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\mdclabuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

<img width="1212" alt="image" src="https://github.com/mdenizcengiz/Threat-Hunting-Scenario/blob/main/Screenshots/4-DeviceNetworkEvents.png">

---

## Chronological Event Timeline 

### 1. Process Execution – TOR Browser Installation

Timestamp: 2025-11-01T17:23:53Z
Event: The user “mdclabuser” executed the file tor-browser-windows-x86_64-portable-15.0.exe in silent mode, initiating a background installation of the TOR Browser.
Action: Process creation detected.
Command: tor-browser-windows-x86_64-portable-15.0.exe /S
Device: threat-hunt-lab
File Path: C:\Users\mdclabuser\Downloads\tor-browser-windows-x86_64-portable-15.0.exe

### 2. File Creation – TOR Browser Installation Files

Timestamps:

2025-11-01T17:23:56Z – File created by installer

2025-11-01T17:24:21Z – Additional TOR Browser-related file created
Event: Installation generated new files within the Tor Browser directory, confirming that the setup completed successfully.
Action: File creation by installer process.
Process: tor-browser-windows-x86_64-portable-15.0.exe /S
User: mdclabuser

### 3. Network Connection – TOR Network

Timestamp: 2025-11-01T17:24:53Z
Event: The TOR process (tor.exe) established an outbound connection to IP 66.70.211.20 on port 9001, indicating initial TOR network connection setup.
Action: Connection success.
Process: tor.exe
File Path: C:\Users\mdclabuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 4. Additional Network Connections – TOR Activity

Timestamps:

2025-11-01T17:24:54Z – Connection to 37.46.211.102:443

2025-11-01T17:25:01Z – Connection to 51.75.129.204:443

2025-11-01T17:25:03Z – Connection to 127.0.0.1:9150 

2025-11-01T17:26:07Z – Connection to 51.75.129.204:443

Event: Multiple TOR network connections were established, confirming ongoing encrypted browsing sessions.
Action: Multiple successful connections detected.
Processes: tor.exe, firefox.exe
User: mdclabuser

### 5. File Creation – TOR Shopping List

Timestamp: 2025-11-01T17:42:28Z
Event: The user “mdclabuser” created and later modified a text file named tor-shopping-list.txt on the desktop.
Action: File creation and modification detected.
File Path: C:\Users\mdclabuser\Desktop\tor-shopping-list.txt
Related Actions:

.lnk shortcut created in AppData\Roaming\Microsoft\Windows\Recent

File content modified at 2025-11-01T17:43:16Z

### 6. File Creation – TOR Browser User Data

Timestamps:

2025-11-01T17:50:25Z – File formhistory.sqlite created

2025-11-01T17:24:42Z – File storage-sync-v2.sqlite created
Event: TOR browser generated user data files (.sqlite) related to browsing form history and storage sync.
Action: File creation detected within the TOR profile folder.
Folder Path:
C:\Users\mdclabuser\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default


## Summary

The user **"mdclabuser"** on the **"threat-hunt-lab"** device initiated and completed the installation of the **TOR Browser (v15.0)** using a silent installation command. Following installation, the user executed TOR-related processes (`tor.exe` and `firefox.exe`), which successfully established multiple encrypted connections to TOR network nodes and a local SOCKS proxy.

Subsequently, several files associated with TOR browser activity were created, including browsing database files (`formhistory.sqlite`, `storage-sync-v2.sqlite`) and a user-generated text file named **`tor-shopping-list.txt`** located on the desktop. These artifacts confirm that the user not only installed and configured the TOR browser but also actively engaged in anonymous browsing activity and maintained local notes potentially related to that usage.

---
