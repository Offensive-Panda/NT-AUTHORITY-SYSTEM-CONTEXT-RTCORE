# NT-AUTHORITY-SYSTEM-CONTEXT-RTCORE
This exploit rebuilds and exploit the CVE-2019-16098 which is in driver Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. Instead of hardcoded base address of Ntoskrnl.exe, I calculated it dynamically and also calculated all offsets for new version of windows. EPROCESS structure is an opaque structure that serves as the process object for a process and the PsInitialSystemProcess global variable points to the process object for the system process. So for calculate the offsetPsInitialSystemProcess address we need Ntoskrnl.exe base address which we calculated dynamically and after that calculated all fields within EPROCESS structure needed to steal system token and escalate priviliges. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.


https://github.com/user-attachments/assets/64295738-987a-4309-811a-c8805d788e05



## Flow of code
* Define required structure needed for RTCORE64 read and write operations.
* Calculated the base address of Ntoskrnl.exe
* Calculated the offset and address of PsInitialSystemProcess
* Calculated the offsets for required fields under EPROCESS Structure (Token, UniqueProcessId, ActiveProcessLinks)
* Use the device object to steal and write the token of System process.
* Elevated with System Context.

## Usage 
* Build and compile the program with visual studio 2019
* Start service before execution of compiled binary.
* Run command to create service (sc create RTCORE64 binPath="Path of Driver File" type=kernel)
* Start the service (sc start RTCORE64
* Run the compiled binary and get NT-AUTHORITY\SYSTEM

## NOTE
* Tested on windows 11 23H2 with releaseID 2009, Build Number 22621.3447 and major version 10.
* New releases and build numbers can have different offsets.
* This code is utilizing the technique of PPLKiller to get based address of Ntoskrnl.exe.

### Disclaimer
Only for educational purposes.

### References
https://github.com/Barakat/CVE-2019-16098
https://github.com/RedCursorSecurityConsulting/PPLKiller



