using System;
using System.Security.Principal;

namespace SystemFingerprint
{
    class Program
    {
        static void Main(string[] args)
        {
            WindowsPrincipal wp = new WindowsPrincipal(WindowsIdentity.GetCurrent());

            if (!wp.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine("\nError: Run this application with Administrative privlagies.");
                return;
            }

            Fingerprint fp = new Fingerprint();
            
            string output = String.Format("\nUnique System Fingerprint:\n{0}\n" +
                                          "\nBased on the following measurements:\n" +
                                          "\nMeasureBaseboard = {1}" +
                                          "\nMeasureBios = {2}" +
                                          "\nMeasureCpu = {3}" +
                                          "\nMeasureTpm (if available) = {4}" +
                                          "\nMeasureActiveNICs = {5}" +
                                          "\nMeasureVideoboard = {6}" + 
                                          "\nMeasureOSSerialNumber = {7}" +
                                          "\nMeasureSystemUUID = {8}" +
                                          "\nMeasureHDDSerialNumber = {9}",
                                          fp.Generate(), fp.MeasureBaseboard.ToString(), fp.MeasureBios.ToString(),
                                          fp.MeasureCpu.ToString(), fp.MeasureTpm.ToString(), fp.MeasureActiveNICs.ToString(), 
                                          fp.MeasureVideoboard.ToString(), fp.MeasureOSSerialNumber.ToString(), 
                                          fp.MeasureSystemUUID.ToString(), fp.MeasureHDDSerialNumber.ToString());

            Console.WriteLine(output);            
        }
    }
}
