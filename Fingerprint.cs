using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace SystemFingerprint
{
    internal class Fingerprint
    {
        private List<WMIQueryObj> queryItems = new List<WMIQueryObj>();
        private string result = String.Empty;
        private bool bParamsChanged = true;
        private bool bMeasureBaseboard, bMeasureBios, bMeasureCpu, bMeasureVideoboard, bMeasureActiveNICs, 
                     bMeasureTpm, bMeasureOSSerialNumber, bMeasureSystemUUID, bMeasureHDDSerialNumber;
        
        /// <summary>
        /// Measurement includes CPU UniqueId, ProcessorID, Name and Manufacturer.
        /// Will be constant on a system unless the CPU is replaced.
        /// Possible to have two systems return same values as many CPUs no longer support the UniqueId value.
        /// </summary>
        internal bool MeasureCpu
        {
            set
            {
                bMeasureCpu = value;
                this.IncludeCpuQueries(value);
                this.bParamsChanged = true;
            }

            get { return bMeasureCpu; }
        }

        /// <summary>
        /// Measurement includes BIOS Serial Number, Identification Code and Manufacturer.
        /// Will be constant on a system as it is difficult to modify BIOS values. Unless the BIOS vendor changes values on newer versions, rarely done.
        /// Very difficult to have two physical systems with same BIOS Serial Number. 
        /// Possible to have two virtual systems with BIOS Serial Number.
        /// </summary>
        internal bool MeasureBios
        {
            set
            {
                bMeasureBios = value;
                this.IncludeBiosQueries(value);
                this.bParamsChanged = true;
            }

            get { return bMeasureBios; }
        }

        /// <summary>
        /// Measurement includes Motherboard Model, Serial Number, Name and Manufacturer.
        /// Will be constant on a system as it is difficult to modify the serial number of the motherboard.
        /// Virtual systems may not support/provide values for the motherboard.
        /// </summary>
        internal bool MeasureBaseboard
        {
            set
            {
                bMeasureBaseboard = value;
                this.IncludeBaseboardQueries(value);
                this.bParamsChanged = true;
            }

            get { return bMeasureBaseboard; }
        }

        /// <summary>
        /// Measurement includes the Windows Serial Number which is unique to this installation of the OS.
        /// Will only change for systems with different installation and product keys.
        /// </summary>
        internal bool MeasureOSSerialNumber
        {
            set
            {
                bMeasureOSSerialNumber = value;
                this.IncludeOSSerialNumberQueries(value);
                this.bParamsChanged = true;
            }

            get { return bMeasureOSSerialNumber; }
        }

        /// <summary>
        /// Measurement includes the UUID of the motherboard.
        /// This UUID value is support by both physical and virtual systems.
        /// Some non-OEM vendors may not populate this UUID.
        /// </summary>
        internal bool MeasureSystemUUID
        {
            set
            {
                bMeasureSystemUUID = value;
                this.IncludeSystemUUIDQueries(value);
                this.bParamsChanged = true;
            }

            get { return bMeasureSystemUUID; }
        }

        /// <summary>
        /// Measurement includes the Serial Number of the hard disk on which the OS is installed.
        /// This value can change is the hard disk is replaced.
        /// </summary>
        internal bool MeasureHDDSerialNumber
        {
            set
            {
                bMeasureHDDSerialNumber = value;
                this.bParamsChanged = true;
            }

            get { return bMeasureHDDSerialNumber; }
        }

        /// <summary>
        /// Measurement includes the PNP Device ID of the video card. Which includes the Vendor ID, Device ID and Serial Number.
        /// This value can change if the video card is replaced.
        /// The Serial Number is provided via the INF file and not directly by the hardware and therefore can be altered.
        /// </summary>
        internal bool MeasureVideoboard
        {
            set
            {
                bMeasureVideoboard = value;
                this.IncludeVideoboardQueries(value);
                this.bParamsChanged = true;
            }

            get { return bMeasureVideoboard; }
        }

        /// <summary>
        /// Measurement includes the MAC address of all active (ones with IP addresses) network cards. 
        /// MAC addresses can be altered in virtual systems.
        /// </summary>        
        internal bool MeasureActiveNICs
        {
            set
            {
                bMeasureActiveNICs = value;
                this.IncludeNICsQueries(value);
                this.bParamsChanged = true;
            }

            get { return bMeasureActiveNICs; }
        }

        /// <summary>
        /// Measurement includes the Platform Configuration Register (PCR) value of the Trusted Platform Module (TPM), if available on the system.
        /// Limited to physical systems with a TPM device, not available on virtual systems.
        /// TPM Platform Config Register PCR[0] typically represents a consistent view of the platform. 
        /// It contains measurements made by the BIOS during system power on. 
        /// These measurements include, but are not limited to:
        ///  - Platform firmware physically bound to the motherboard
        ///  - S2/S3 resume code
        ///  - SMM code
        ///  - ACPI flash data
        ///  - Option ROM binary images
        /// </summary>
        internal bool MeasureTpm
        {
            set
            {
                bMeasureTpm = value;                
                this.bParamsChanged = true;
            }

            get { return bMeasureTpm; }
        }

        /// <summary>
        /// Initializes with measurements of all available metrics.
        /// </summary>
        internal Fingerprint()
        {
            this.MeasureBaseboard = true;
            this.MeasureBios = true;
            this.MeasureCpu = true;
            this.MeasureTpm = true;
            this.MeasureOSSerialNumber = true;
            this.MeasureSystemUUID = true;
            this.MeasureHDDSerialNumber = true;
            this.MeasureVideoboard = true;
            this.MeasureActiveNICs = true;
        }

        internal string Generate()
        {
            if (bParamsChanged)
            {
                string value = null;
                StringBuilder sbValues = new StringBuilder();

                foreach (WMIQueryObj wmiQuery in this.queryItems)
                {
                    ManagementObjectSearcher oWMI = new ManagementObjectSearcher(wmiQuery.QueryString);

                    foreach (ManagementObject mo in oWMI.Get())
                    {
                        value = (string)mo[wmiQuery.Property];
                        if (!String.IsNullOrEmpty(value))
                            sbValues.AppendLine(value);
                    }
                }                

                if (MeasureTpm)
                {
                    value = TpmWrapper.Instance.ReadPCR(0);
                    if (!String.IsNullOrEmpty(value))
                        sbValues.AppendLine(value);
                    else
                        this.bMeasureTpm = false;
                }

                if (MeasureHDDSerialNumber)
                {
                    string logicalDiskId = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)).Substring(0, 2);
                    string deviceSerialNumber = string.Empty;

                    var query = "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='" + logicalDiskId + "'} WHERE AssocClass = Win32_LogicalDiskToPartition";
                    var queryResults = new ManagementObjectSearcher(query);
                    var partitions = queryResults.Get();

                    foreach (var partition in partitions)
                    {
                        query = "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + partition["DeviceID"] + "'} WHERE AssocClass = Win32_DiskDriveToDiskPartition";
                        queryResults = new ManagementObjectSearcher(query);
                        var drives = queryResults.Get();

                        foreach (var drive in drives)
                        {
                            deviceSerialNumber = drive["SerialNumber"].ToString();
                        }
                    }

                    if (!String.IsNullOrEmpty(deviceSerialNumber))
                        sbValues.AppendLine(deviceSerialNumber);
                    else
                        this.bMeasureHDDSerialNumber = false;
                }

                ASCIIEncoding asciEncoding = new ASCIIEncoding();
                byte[] btAsciEncoded = asciEncoding.GetBytes(sbValues.ToString());

                SHA256 sha = new SHA256CryptoServiceProvider();
                btAsciEncoded = sha.ComputeHash(btAsciEncoded);

                this.result = HexFormat.ByteArrayToString(btAsciEncoded);
            }

            return this.result;
        }

        private void IncludeBaseboardQueries(bool bInclude = true)
        {
            this.queryItems.RemoveAll(x => x.Class.ToLower().Contains("baseboard"));

            if (bInclude)
            {
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_BaseBoard", Property = "Model" });
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_BaseBoard", Property = "Manufacturer" });
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_BaseBoard", Property = "Name" });
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_BaseBoard", Property = "SerialNumber" });
            }
        }

        private void IncludeBiosQueries(bool bInclude = true)
        {
            this.queryItems.RemoveAll(x => x.Class.ToLower().Contains("bios"));

            if (bInclude)
            {
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_BIOS", Property = "Manufacturer" });
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_BIOS", Property = "IdentificationCode" });
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_BIOS", Property = "SerialNumber" });
            }
        }

        private void IncludeCpuQueries(bool bInclude = true)
        {
            this.queryItems.RemoveAll(x => x.Class.ToLower().Contains("processor"));

            if (bInclude)
            {
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_Processor", Property = "UniqueId" });
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_Processor", Property = "ProcessorId" });
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_Processor", Property = "Name" });
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_Processor", Property = "Manufacturer" });
            }
        }

        private void IncludeOSSerialNumberQueries(bool bInclude = true)
        {
            this.queryItems.RemoveAll(x => x.Class.ToLower().Contains("operatingsystem"));

            if (bInclude)
            {
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_OperatingSystem", Property = "SerialNumber" });
            }
        }

        private void IncludeSystemUUIDQueries(bool bInclude = true)
        {
            this.queryItems.RemoveAll(x => x.Class.ToLower().Contains("computersystemproduct "));

            if (bInclude)
            {
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_ComputerSystemProduct ", Property = "UUID" });
            }
        }

        private void IncludeVideoboardQueries(bool bInclude = true)
        {
            this.queryItems.RemoveAll(x => x.Class.ToLower().Contains("videocontroller"));

            if (bInclude)
            {
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_VideoController", Property = "PNPDeviceID" });
            }
        }

        private void IncludeNICsQueries(bool bInclude = true)
        {
            this.queryItems.RemoveAll(x => x.Class.ToLower().Contains("networkadapter"));

            if (bInclude)
            {
                this.queryItems.Add(new WMIQueryObj() { Class = "Win32_NetworkAdapterConfiguration", Property = "MACAddress", AppendCustomQuery = "WHERE IPEnabled = \"true\"" });
            }
        }
    }

    internal class WMIQueryObj
    {
        internal string Class { get; set; }

        internal string Property { get; set; }

        internal string AppendCustomQuery { get; set; }

        internal string QueryString
        {
            get 
            {
                if (String.IsNullOrWhiteSpace(AppendCustomQuery))
                    return string.Format("SELECT {0} FROM {1}", Property, Class);
                else
                    return string.Format("SELECT {0} FROM {1} {2}", Property, Class, AppendCustomQuery);
            }
        }
    }
}