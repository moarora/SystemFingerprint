# System Fingerprint

### Summary
Generates a unique system value based on various system metrics for Microsoft Windows systems.

### Requirements
.NET Framework v4.5.2

### Build
Use Visual Studio 2013

### Usage
Run 'SystemFingerprint.exe' on the command line with elevated privileges.

### Metrics Used for Measurement
1. CPU   
   Measurement includes CPU UniqueId, ProcessorID, Name and Manufacturer.
   Will be constant on a system unless the CPU is replaced.
   Possible to have two systems return same values as many CPUs no longer support the UniqueId value.

2. BIOS   
   Measurement includes BIOS Serial Number, Identification Code and Manufacturer.
   Will be constant on a system as it is difficult to modify BIOS values. Unless the BIOS vendor changes values on newer versions, rarely done.
   Very difficult to have two physical systems with same BIOS Serial Number. 
   Possible to have two virtual systems with BIOS Serial Number.

3. Baseboard   
   Measurement includes Motherboard Model, Serial Number, Name and Manufacturer.
   Will be constant on a system as it is difficult to modify the serial number of the motherboard.
   Virtual systems may not support/provide values for the motherboard.

4. TPM (Trusted Platform Module)   
   Measurement includes the Platform Configuration Register (PCR) value of the Trusted Platform Module (TPM), if available on the system.
   Limited to physical systems with a TPM device, not available on virtual systems.
   TPM Platform Config Register PCR[0] typically represents a consistent view of the platform. 
   It contains measurements made by the BIOS during system power on. 
   These measurements include, but are not limited to:
    - Platform firmware physically bound to the motherboard
    - S2/S3 resume code
    - SMM code
    - ACPI flash data
	- Option ROM binary images

5. Windows Serial Number   
   Measurement includes the Windows Serial Number which is unique to this installation of the OS.
   Will only change for systems with different installation and product keys.

6. System UUID   
   Measurement includes the UUID of the motherboard.
   This UUID value is support by both physical and virtual systems.
   Some non-OEM vendors may not populate this UUID.

7. HDD Serial Number   
   Measurement includes the Serial Number of the hard disk on which the OS is installed.
   This value can change if the hard disk is replaced.

8. Video Card   
   Measurement includes the PNP Device ID of the video card. Which includes the Vendor ID, Device ID and Serial Number.
   This value can change if the video card is replaced.
   The Serial Number is provided via the INF file and not directly by the hardware and therefore can be altered.

9. Network Card MAC Address   
   Measurement includes the MAC address of all active (ones with IP addresses) network cards. 
   MAC addresses can be altered in virtual systems.
