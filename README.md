# MasonRadar

When you first open MasonRadar you see a clean drop zone where you can drag and drop any executable or click to browse for one

![File Selection](https://i.ibb.co/tM8xqX6q/image.png)

After launching a process the Monitor tab shows all network connections with protocol detection along with extracted URLs and domains from memory in separate sections each with its own search bar

![Monitor Tab](https://i.ibb.co/fzbHVKCQ/image.png)

The Memory Explorer tab gives you a full raw dump of every printable string found in the process memory showing the address, length, encoding type, and protection level for each entry

![Memory Explorer](https://i.ibb.co/JWVQ9wCB/image.png)

## What it does

MasonRadar is a lightweight Windows desktop tool built in Delphi that lets you launch any executable in a restricted environment and watch what it does in real time. It monitors all outgoing and incoming network connections showing you exactly which IPs and ports the process talks to and what protocols it uses. It also scans the process memory to extract URLs, domains, and IP addresses that the program stores internally even if it hasn't connected to them yet. The Memory Explorer tab gives you a full dump of every readable string in the process memory with address, encoding, and protection level. Everything accumulates over time so nothing gets lost, and you can export a full report with one click.

## Process Execution

Launches the target process using CreateProcess with an attempt to apply a restricted token and low integrity level to limit what the process can access on the system. Falls back to standard launch if restrictions cannot be applied.

## Network Monitoring

Uses the Windows IP Helper API through GetExtendedTcpTable and GetExtendedUdpTable to enumerate all TCP and UDP connections belonging to the target process. Each connection shows the local and remote IP, port numbers, current state, and an automatic protocol detection based on well-known ports covering HTTP, HTTPS, DNS, SSH, FTP, RDP, SMTP, WebSocket, and more.

## Memory Inspection

Walks the entire virtual address space of the target process using VirtualQueryEx and reads committed memory regions with ReadProcessMemory. Extracts printable strings in both ASCII and UTF-16 encodings then classifies them as URLs, domain names, IPv4 addresses, IPv6 addresses, or hostnames. Includes strict validation against a list of real TLDs and filters out false positives like .NET namespaces, DLL names, and version strings.

## Memory Explorer

A dedicated tab that shows every printable string found in the process memory regardless of category. Each entry displays the memory address, string length, encoding type, and memory protection level. Supports searching and filtering across tens of thousands of strings.

## Persistent Data

All discovered connections, URLs, domains, and IPs accumulate over time and never disappear until you press Clear. Connection states update automatically. This ensures you capture everything even if a connection is brief.

## Search and Filter

Every section has its own search bar that filters results instantly without re-scanning. Works across all columns so you can search by IP, port, protocol, domain, or any keyword.

## Save Report

Exports a complete text report containing all network connections, discovered URLs, domains, and IPs with a single click. The report is timestamped and formatted for easy reading.

## Right-Click Copy

Right-click any row in any list to copy its contents to the clipboard.

## Custom Interface

Dark themed borderless window with a custom title bar supporting drag to move, double-click to maximize, and corner resize grips. Minimize, maximize, and close buttons with hover effects.

## How it works

MasonRadar uses only native Windows APIs with no external libraries or dependencies.

For network monitoring it calls GetExtendedTcpTable and GetExtendedUdpTable from iphlpapi.dll filtering results by the target process ID.

For memory scanning it opens the process with PROCESS_VM_READ and PROCESS_QUERY_INFORMATION access, iterates through memory regions with VirtualQueryEx, reads each committed readable region with ReadProcessMemory, and extracts both ASCII and UTF-16 printable strings. Each string is then classified using pattern matching with validation against known TLDs and rejection of common false positives.

For restricted execution it uses CreateRestrictedToken with DISABLE_MAX_PRIVILEGE to strip most privileges from the child process token, then lowers the integrity level to Low using SetTokenInformation with a low mandatory integrity SID.

## Building

Open src\MasonRadar.dproj in Embarcadero RAD Studio or Delphi 12 and press F9. The output executable will be placed in the build folder. No external libraries or packages are required.

## Project Structure

The src folder contains MasonRadar.dpr as the entry point and MasonRadar.dproj as the RAD Studio project file. Inside src\units you will find uWinTypes.pas which holds all shared Windows API type declarations and function imports from iphlpapi.dll and advapi32.dll, uProcessControl.pas which handles process launching with restricted tokens and lifecycle tracking, uNetworkMonitor.pas which enumerates TCP and UDP connections for a specific process ID with protocol detection, and uMemoryScanner.pas which performs both network-focused scans and full memory scans returning every printable string with metadata. Inside src\forms you will find uMainForm.pas which builds the entire GUI programmatically including the custom title bar and two-tab interface, and uMainForm.dfm which is the form resource file.

## Requirements

Windows 7 or later. Administrator privileges recommended for full memory access to target processes. Protected or PPL processes will not be readable.

## Limitations

The restricted token approach reduces the child process privileges but is not a full sandbox and cannot prevent all forms of system access. Memory scanning is capped at 4 MB per region to keep refresh times reasonable. Protocol detection is based on well-known port numbers and does not perform deep packet inspection. The Memory Explorer tab limits display to 30000 strings for performance.
