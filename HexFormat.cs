using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace SystemFingerprint
{
    class HexFormat
    {
        public static string RemoveWhiteSpaces(string hex)
        {
            hex = hex.Trim();
            hex = hex.Replace("\r", string.Empty);
            hex = hex.Replace("\n", string.Empty);
            hex = hex.Replace(" ", string.Empty);
            return hex;
        }

        public static bool IsValidHexStr(string hex)
        {
            Match m = Regex.Match(RemoveWhiteSpaces(hex), @"^[A-Fa-f0-9]*$");

            if (m.Success && hex.Length % 2 == 0)
                return true;
            return false;
        }        

        public static string FormatBytes(string hex, int nBreakOnBytes = 2)
        {
            int numBreaks = 0;

            if (IsValidHexStr(hex))
            {
                string str = RemoveWhiteSpaces(hex);
                for (int i = 0; i < hex.Length; i++)
                {
                    if ((i + 1) % (nBreakOnBytes * 2) == 0 && (i + 1) != hex.Length)
                    {
                        int insert = i + 1 + numBreaks * 2;
                        str = str.Insert(insert, Environment.NewLine);
                        numBreaks++;
                    }
                }
                return str;
            }
            return null;
        }       

        public static string ByteArrayToString(byte[] hexArray, bool bAddSpaces = false)
        {
            StringBuilder sb = new StringBuilder(hexArray.Length);

            foreach (byte singleByte in hexArray)
            {
                sb.Append(singleByte.ToString("X2"));
                if (bAddSpaces) sb.Append(" ");
            }

            return sb.ToString().Trim();
        }

        public static byte[] StringToByteArray(string hexString)
        {
            if (IsValidHexStr(hexString))
            {
                string s = RemoveWhiteSpaces(hexString);

                byte[] b = new byte[s.Length / 2];

                for (int i = 0; i < s.Length; i += 2)
                {
                    b[i / 2] = byte.Parse(s[i].ToString() + s[i + 1].ToString(), System.Globalization.NumberStyles.HexNumber);
                }
                return b;
            }
            return null;
        }
    }
}
