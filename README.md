# MasonRadar

Real-time process inspection tool that monitors network activity, detects API hooks, scans for XOR-encoded strings, finds embedded payloads, and extracts hidden URLs and IPs from process memory

![Tool](https://i.ibb.co/DD4zZZ4V/image.png)

## What it does

MasonRadar launches any Windows executable in a restricted low-integrity environment and watches everything it does at runtime. It tracks all TCP and UDP connections with automatic protocol detection, scans process memory for URLs, domains, and IP addresses in both ASCII and UTF-16 encodings, detects API hooking by reading the first bytes of critical Windows functions, finds XOR-encoded strings by brute-forcing single-byte keys against known patterns, identifies encrypted or packed memory regions through Shannon entropy analysis, lists all loaded DLLs and flags suspicious modules like sandbox detectors or hooking frameworks, extracts file paths and registry keys the process accesses, and locates embedded PE executables hidden in memory that can be exported as files. Everything accumulates over time and nothing disappears until you press Clear.

## Tabs

MasonRadar organizes its output across six tabs so each section gets full screen space.

**Monitor** shows network connections with protocol detection covering HTTP, HTTPS, DNS, SSH, FTP, RDP, SMTP, and WebSocket. Below that it shows URLs and links extracted from memory in a dedicated section, followed by domains and IP addresses found in memory with classification into Domain, IPv4, IPv6, and Hostname categories.

**Memory** provides a full raw dump of every printable string found in the process memory regardless of category. Each entry shows the memory address, string length, encoding type (ASCII or UTF-16), and memory protection level.

**Hooks** reads the first 16 bytes of 25 critical Windows API functions from kernel32, ntdll, ws2_32, and wininet inside the target process and checks for JMP, PUSH+RET, or MOV+JMP patterns that indicate hooking. It shows the raw bytes and whether each function is Clean or HOOKED.

**Crypto / XOR** has two sections. The top half scans memory for strings that decode to URLs when XOR'd with a single-byte key, showing the key value, address, and decoded content. The bottom half identifies memory blocks with Shannon entropy above 7.2 out of 8.0, which indicates encrypted or compressed data, showing the address, size, entropy value, and protection level.

**Modules / Paths** lists all DLLs loaded by the process with their full paths, shows file paths and registry keys found in memory classified by type (FilePath, Registry, UNC, ConfigFile), and flags suspicious modules that match known names associated with sandboxes, debuggers, hooking frameworks, or analysis tools.

**Payloads** scans memory for embedded PE executables by looking for MZ headers followed by valid PE signatures. It identifies whether each payload is PE32 (x86) or PE32+ (x64) and shows the address, size, and protection level. Right-clicking a payload lets you export it as a .bin or .exe file.

## Start and Scan

The **Start** button launches the target process and begins continuous real-time monitoring. Data refreshes every 3 seconds with the workload split across light, medium, and heavy scan cycles to keep the interface responsive.

The **Scan** button launches the process and runs a full automated scan for 60 seconds. During the scan a progress bar shows the elapsed time. After 60 seconds MasonRadar automatically stops the process, generates a complete text report in the same folder as the scanned file, and opens the report in your default text editor.

## How it works

MasonRadar uses only native Windows APIs with no external libraries.

For network monitoring it calls GetExtendedTcpTable and GetExtendedUdpTable from iphlpapi.dll filtering results by the target process ID.

For memory scanning it opens the process with PROCESS_VM_READ and PROCESS_QUERY_INFORMATION access, iterates through memory regions with VirtualQueryEx, reads each committed readable region with ReadProcessMemory, and extracts both ASCII and UTF-16 printable strings. Network-related strings are classified using pattern matching with validation against 50 known TLDs and rejection of common false positives like .NET namespaces and DLL names.

For hook detection it uses GetModuleHandle and GetProcAddress to find the address of each monitored API function, then reads the first 16 bytes from that address inside the target process and checks for known hooking instruction patterns.

For XOR scanning it walks memory and for each byte checks if XORing it with a candidate key produces the letter 'h'. If it does, it tries decoding the next bytes to see if they spell 'http'. When a match is found it decodes the full string and records the key and address.

For entropy analysis it divides each memory region into 4KB blocks and calculates the Shannon entropy of each block. Blocks scoring above 7.2 are flagged as potentially encrypted or packed.

For payload detection it scans memory for the MZ signature (0x4D5A) followed by a valid PE signature (0x00004550) at the offset specified in the DOS header, then reads the machine type to determine if it's x86 or x64.

For restricted execution it uses CreateRestrictedToken with DISABLE_MAX_PRIVILEGE to strip most privileges from the child process token, then lowers the integrity level to Low using SetTokenInformation.

## Building

Open src\MasonRadar.dproj in Embarcadero RAD Studio or Delphi 12 and press F9. No external libraries or packages are required.

## Project Structure

The src folder contains MasonRadar.dpr as the entry point and MasonRadar.dproj as the RAD Studio project file. Inside src\units there are five modules. uWinTypes holds all shared Windows API type declarations and function imports. uProcessControl handles process launching with restricted tokens and lifecycle tracking. uNetworkMonitor enumerates TCP and UDP connections per PID with protocol detection. uMemoryScanner performs both network-focused scans and full raw memory scans extracting ASCII and UTF-16 strings. uAdvanced handles hook detection, XOR string scanning, entropy analysis, suspicious module detection, file path extraction, loaded module enumeration, embedded payload scanning, and payload export. Inside src\forms there is uMainForm.pas which builds the entire six-tab GUI programmatically, and uMainForm.dfm which is the form resource file.

## Requirements

Windows 7 or later. Administrator privileges recommended for full memory access. Protected or PPL processes will not be readable.

## Limitations

The restricted token approach reduces privileges but is not a full sandbox. Memory scanning is capped at 4 MB per region. Protocol detection is port-based only. The Memory tab limits display to 30000 strings. XOR scanning only detects single-byte keys against HTTP URL patterns. Entropy threshold is fixed at 7.2 and block size at 4KB.
