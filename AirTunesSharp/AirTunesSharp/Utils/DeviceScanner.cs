using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Tmds.MDns;
using AirTunesSharp.Devices;
using System.Numerics;

namespace AirTunesSharp.Utils
{
    /// <summary>
    /// Get list of all AirPlay/RAOP devices on the network
    /// </summary>
    public class DeviceScanner
    {
        private ServiceBrowser? serviceBrowserRAOP;
        private ServiceBrowser? serviceBrowserAirPlay;
        private List<Dictionary<String, dynamic>> devices = new List<Dictionary<String, dynamic>>();
        public DeviceScanner()
        {

        }


        public async void StartScanning()
        {

            serviceBrowserRAOP = new ServiceBrowser();
            serviceBrowserRAOP.ServiceAdded += onServiceAdded;
            serviceBrowserRAOP.ServiceRemoved += onServiceRemoved;
            serviceBrowserRAOP.ServiceChanged += onServiceChanged;

            Console.WriteLine("Browsing for type: {0}", "_raop._tcp");
            serviceBrowserRAOP.StartBrowse("_raop._tcp");

            serviceBrowserAirPlay = new ServiceBrowser();
            serviceBrowserAirPlay.ServiceAdded += onServiceAdded;
            serviceBrowserAirPlay.ServiceRemoved += onServiceRemoved;
            serviceBrowserAirPlay.ServiceChanged += onServiceChanged;
            serviceBrowserAirPlay.StartBrowse("_airplay._tcp");
            Console.WriteLine("Browsing for type: {0}", "_airplay._tcp");

        }

        public void StopScanning()
        {
            if (serviceBrowserRAOP != null) {
            serviceBrowserRAOP.StopBrowse();
            serviceBrowserRAOP.ServiceAdded -= onServiceAdded;
            serviceBrowserRAOP.ServiceRemoved -= onServiceRemoved;
            serviceBrowserRAOP.ServiceChanged -= onServiceChanged;
            serviceBrowserRAOP = null;}

            if (serviceBrowserAirPlay != null) {
            serviceBrowserAirPlay.StopBrowse();
            serviceBrowserAirPlay.ServiceAdded -= onServiceAdded;
            serviceBrowserAirPlay.ServiceRemoved -= onServiceRemoved;
            serviceBrowserAirPlay.ServiceChanged -= onServiceChanged;
            serviceBrowserAirPlay = null;}


        }

        private void onServiceChanged(object sender, ServiceAnnouncementEventArgs e)
        {
            //  printService('~', e.Announcement);
            // devices.RemoveAll(x => x["key"] == e.Announcement.Addresses[0].ToString() + ":" + e.Announcement.Port.ToString());
            // devices.Add(new Dictionary<String, dynamic>()
            //     {
            //         { "key" , e.Announcement.Addresses[0].ToString()+ ":" + e.Announcement.Port.ToString() },
            //         { "name", e.Announcement.Instance },
            //         { "host", e.Announcement.Addresses[0].ToString() },
            //         { "port", e.Announcement.Port.ToString() },
            //         { "txt", e.Announcement.Txt },
            //         { "type", e.Announcement.Type },
            //         { "interface", e.Announcement.NetworkInterface.Name },
            //         { "options", parseTxt(e.Announcement.Txt.ToArray(), e.Announcement.Type == "_airplay._tcp" ) }
            // });
        }

        private void onServiceRemoved(object sender, ServiceAnnouncementEventArgs e)
        {
            // printService('-', e.Announcement);
            // devices.RemoveAll(x => x["key"] == e.Announcement.Addresses[0].ToString() + ":" + e.Announcement.Port.ToString());
        }

        private void onServiceAdded(object sender, ServiceAnnouncementEventArgs e)
        {
            // printService('+', e.Announcement);
            // check if device already exists in list
            string key = e.Announcement.Addresses[0].ToString() + ":" + e.Announcement.Port.ToString();
            if (!devices.Exists(x => ((Dictionary<String, dynamic>)x).GetValueOrDefault("key", "") == key))
            {
                devices = devices.Append(new Dictionary<String, dynamic>()
                {
                    { "key" , key },
                    { "name", e.Announcement.Instance },
                    { "host", e.Announcement.Addresses[0].ToString() },
                    { "port", e.Announcement.Port.ToString() },
                    { "txt", e.Announcement.Txt },
                    { "type", e.Announcement.Type },
                    { "interface", e.Announcement.NetworkInterface.Name },
                    { "options", parseTxt(e.Announcement.Txt.ToArray(), e.Announcement.Type == "_airplay._tcp" ) }
                }).ToList();
            }
            
        }

        static void printService(char startChar, ServiceAnnouncement service)
        {
            Console.WriteLine("{0} '{1}' on {2}", startChar, service.Instance, service.NetworkInterface.Name);
            Console.WriteLine("\tHost: {0} ({1})", service.Hostname, string.Join(", ", service.Addresses));
            Console.WriteLine("\tPort: {0}", service.Port);
            Console.WriteLine("\tTxt : [{0}]", string.Join(", ", service.Txt));
        }

        private Dictionary<String, dynamic> parseTxt(string[] txt, bool airplay2 = false)
        {

            var statusflags = new string[] { };
            int mode = 1;
            bool alacEncoding = true;
            bool needPassword = false;
            bool needPin = false;
            bool transient = false;
            var features = new string[] { };


            //get txt starts with et= and check whether it contains 4
            //if yes, then set mode to 2
            var et = txt.Where(x => x.StartsWith("et=")).FirstOrDefault();
            if (et != null && et.Contains("4"))
            {
                mode = 2;
            }

            var cn = txt.Where(x => x.StartsWith("cn=")).FirstOrDefault();
            if (cn != null && cn.Contains("0"))
            {
                alacEncoding = false;
            }
            //get sf that can starts with sf= or flags=
            var sf = txt.Where(x => x.StartsWith("sf=") || x.StartsWith("flags=")).FirstOrDefault();
            // Get statusflag , convert hexstring (e.g. 0x3343) to binary and split into array
            if (sf != null)
            {             
                var hex = sf.Substring(sf.IndexOf('=') + 1);
                var binary = Convert.ToString(Convert.ToInt32(hex, 16), 2);
                statusflags = binary.ToCharArray().Select(x => x.ToString()).ToArray();
            }

            needPassword = false;
            needPin = false;
            // Console.WriteLine("txt: " + txt.ToString());



            transient = false;
            var ft = txt.Where(x => x.StartsWith("features=") || x.StartsWith("ft=")).FirstOrDefault();
            // Get statusflag , convert hexstring (e.g. 0x3343) to binary and split into array
            if (ft != null)
            {
                var hex = ft.Substring(ft.IndexOf('=') + 1);
                // check if hex and has "," then split into 2 array
                var hex_p1 = "";
                var hex_p2 = "";

                hex_p1 = hex.Split(",")[0];
                hex_p2 = hex.Contains(',') ? hex.Split(',')[1] : "0x";
                var new_hex = hex_p2 + hex_p1.Substring(2);
                // Console.WriteLine("new_hex: " + new_hex);
                // var binary1 = BigInteger.Parse(new_hex, System.Globalization.NumberStyles.HexNumber);

                // var binary_set1 = binary1.ToCharArray().Select(x => x.ToString()).ToArray();
                // var binary2 = Convert.ToString(Convert.ToInt32(hex_p2, 16), 2);
                // var binary_set2 = binary2.ToCharArray().Select(x => x.ToString()).ToArray();
                
                features = Convert.ToString(Convert.ToInt64(new_hex, 16), 2).ToCharArray().Select(x => x.ToString()).ToArray();
                
                if (features.Length > 48)
                { transient = (features[features.Length - 1 - 48] == "1");}
            }

            if (statusflags != null && statusflags.Length > 0)
            {
                bool PasswordRequired = false;
                bool PinRequired = false;
                bool OneTimePairingRequired = false;
                if (statusflags.Length > 7) PasswordRequired = (statusflags[statusflags.Length - 1 - 7] == "1");
                if (statusflags.Length > 3) PinRequired = (statusflags[statusflags.Length - 1 - 3] == "1");
                if (statusflags.Length > 9) OneTimePairingRequired = (statusflags[statusflags.Length - 1 - 9] == "1");
                // Debug.WriteLine("needPss", PasswordRequired, PinRequired, OneTimePairingRequired);
                needPassword = (PasswordRequired || PinRequired || OneTimePairingRequired);
                needPin = (PinRequired || OneTimePairingRequired);
                // transient = (!(PasswordRequired || PinRequired || OneTimePairingRequired));
                // Debug.WriteLine("needPss", needPassword);
            }

            var k = txt.Where(u => u.StartsWith("am=")).ToList();
            string firstK = k.FirstOrDefault() ?? "";
            if (firstK.Contains("AppleTV3,1") || firstK.Contains("AirReceiver3,1") ||
                firstK.Contains("AirRecever3,1") || firstK.Contains("Shairport"))
            {
                alacEncoding = true;
                airplay2 = false;
            }

            // Filter for records starting with "rmodel="
            k = txt.Where(u => u.StartsWith("rmodel=")).ToList();
            firstK = k.FirstOrDefault() ?? "";
            if (firstK.Contains("AppleTV3,1") || firstK.Contains("AirReceiver3,1") ||
                firstK.Contains("AirRecever3,1") || firstK.Contains("Shairport"))
            {
                alacEncoding = true;
                airplay2 = false;
            }

            // Filter for records starting with "manufacturer="
            var manufacturer = txt.Where(u => u.StartsWith("manufacturer=")).ToList();
            bool isSonos = false;
            string firstManufacturer = manufacturer.FirstOrDefault() ?? "";
            if (firstManufacturer.Contains("Sonos"))
            {
                mode = 2;
                needPin = true;
                isSonos = true;
            }

            var pw_raop = txt.Where(u => u.StartsWith("pw=")).ToList();
            string firstPw = pw_raop.FirstOrDefault() ?? "";
            if (firstPw.Contains("true"))
            {
                needPassword = true;
            }
         
  
            // Console.WriteLine("needPin: " + needPin.ToString());
            // Console.WriteLine("needPassword: " + needPassword.ToString());
            // Console.WriteLine("mode-atv: " + mode.ToString());
            // Console.WriteLine("alacEncoding: " + alacEncoding.ToString());
            // // Console.WriteLine("AP2: " + options.airplay2.ToString());
            // Console.WriteLine("transient: " + transient.ToString());

            // var APOptions = new AirTunesOptions();
            // APOptions.alacEncoding = alacEncoding;
            // APOptions.mode = mode;
            // APOptions.needPassword = needPassword;
            // APOptions.needPin = needPin;
            // // APOptions.debug = options.debug;
            // // APOptions.airplay2 = options.airplay2;
            // APOptions.transient = transient;
            // APOptions.txt = txt;

            return new Dictionary<String, dynamic>()
            {
                { "alacEncoding", alacEncoding },
                { "mode", mode },
                { "needPassword", needPassword },
                { "needPin", needPin },
                { "transient", transient },
                { "features", features },
                { "statusflags", statusflags },
                { "isSonos", isSonos },
                { "airplay2", airplay2 },
                { "debug", true },
                { "txt", txt }
            };

        }



        public List<Dictionary<String, dynamic>> GetAirPlayDevices()
        {           
          return devices;
        }
        

    }
}
