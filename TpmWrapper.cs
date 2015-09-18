using System;
using System.Runtime.InteropServices;

namespace SystemFingerprint
{
    internal class TpmWrapper
    {
        private static TpmWrapper _tpmWrapper;

        private IntPtr hContext = IntPtr.Zero;

        [DllImport("tbs.dll")]
        private unsafe static extern UInt32 Tbsi_Context_Create(UInt32* version, IntPtr* hContext);

        [DllImport("tbs.dll")]
        private unsafe static extern UInt32 Tbsip_Context_Close(IntPtr hContext);

        [DllImport("tbs.dll")]
        private unsafe static extern UInt32 Tbsip_Submit_Command(IntPtr hContext, UInt32 Locality, UInt32 Priority, byte* pCommandBuf, UInt32 CommandBufLen, byte* pResultBuf, UInt32* pResultBufLen);

        private TpmWrapper()
        {
            if (hContext != IntPtr.Zero)
                return;

            unsafe
            {
                UInt32 version = 1;
                IntPtr handle = IntPtr.Zero;
                if (Tbsi_Context_Create(&version, &handle) == 0)
                {
                    hContext = handle;
                }
            }
        }

        ~TpmWrapper()
        {
            if (hContext == IntPtr.Zero)
                return;

            unsafe
            {
                UInt32 tbs_result = Tbsip_Context_Close(hContext);
                if (tbs_result == 0)
                {
                    hContext = IntPtr.Zero;
                }
            }
        }

        private byte[] SubmitCommand(byte[] command, UInt32 respondSize)
        {
            if (hContext == IntPtr.Zero)
                return null;

            unsafe
            {
                UInt32 tbs_result;
                byte[] res = new byte[respondSize];
                uint cmdSize = (uint)command.Length;
                uint resSize = respondSize;

                fixed (byte* pCmd = command, pRes = res)
                {
                    tbs_result = Tbsip_Submit_Command(hContext, 0, 200, pCmd, cmdSize, pRes, &resSize);
                }

                if (tbs_result != 0)
                {
                    hContext = IntPtr.Zero;
                    return null;
                }
                return res;
            }
        }

        internal static TpmWrapper Instance
        {
            get
            {
                if (_tpmWrapper == null)
                    _tpmWrapper = new TpmWrapper();
                return _tpmWrapper;
            }
        }

        /// <summary>
        /// Reads the selected PCR Index of the TPM.
        /// </summary>
        /// <param name="pcrIndex">PCR Index 0 - 23</param>
        /// <returns>20-byte hex value in a string</returns>
        internal string ReadPCR(int pcrIndex)
        {
            if (pcrIndex < 0 || pcrIndex > 23)
                throw new ArgumentOutOfRangeException("pcrIndex", "Invalid TPM PCR Index");

            string cmd = @"00c1"        // tag = TPM_TAG_RQU_COMMAND
                       + @"0000000e"    // paramSize
                       + @"00000015"    // ordinal = TPM_ORD_PCRRead
                       + pcrIndex.ToString("X8");

            byte[] res = this.SubmitCommand(HexFormat.StringToByteArray(cmd), 30);

            if (res != null)
            {
                string sRes = HexFormat.ByteArrayToString(res);

                //string tag = sRes.Substring(0, 4);
                //string paramSize = sRes.Substring(4, 8);
                string returnCode = sRes.Substring(12, 8);
                string outDigest = sRes.Substring(20, 40);

                int rc = Int32.Parse(returnCode, System.Globalization.NumberStyles.HexNumber);

                if (rc == 0)
                {
                    return outDigest;
                }
            }

            return null;
        }
    }
}
