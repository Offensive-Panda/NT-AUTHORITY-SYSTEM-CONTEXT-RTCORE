# NT-AUTHORITY-SYSTEM-CONTEXT-RTCORE
This exploit rebuilds and exploit the CVE-2019-16098 which is in driver Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. Instead of hardcoded base address of Ntoskrnl.exe, I calculated it dynamically and also calculated all offsets.
