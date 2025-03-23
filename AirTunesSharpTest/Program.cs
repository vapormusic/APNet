using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using AirTunesSharp;
using Makaretu.Dns;

namespace AirTunesSharpTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("AirTunesSharp Test Application");
            Console.WriteLine("------------------------------");


            
            try
            {
                // Create an instance of AirTunes
                var airTunes = new AirTunes();
                Console.WriteLine("AirTunes instance created successfully");

                // Load audio data from output.pcm
                Console.WriteLine("Loading audio data from output.pcm...");
                byte[] audioData = System.IO.File.ReadAllBytes("C:\\Users\\vapormusic\\Downloads\\aaaa\\AirTunesSharpTest\\output.pcm");

                var idx = 0;

                // Set up event handlers
                airTunes.On("device", (eventArgs) => {
                    string key = eventArgs[0].ToString();
                    string status = eventArgs[1].ToString();
                    string desc = eventArgs.Length > 2 ? eventArgs[2]?.ToString() : null;
                    
                    Console.WriteLine($"Device event: {key} - {status} {(desc != null ? $"({desc})" : "")}");
                });
                
                airTunes.On("buffer", (eventArgs) => {
                    Console.WriteLine($"Buffer event: {eventArgs[0]}");
                });
                
                airTunes.On("drain", (eventArgs) => {
                    Console.WriteLine("Drain event");
                    airTunes.Write(audioData.Skip(352 * 4 * idx).Take(352 * 4 * 300).ToArray());
                    idx += 300;
                });
                
                airTunes.On("error", (eventArgs) => {
                    Console.WriteLine($"Error event: {eventArgs[0]}");
                });
                
                Console.WriteLine("Event handlers registered");
                
                // Look for ShairportQt devices
                Console.WriteLine("Looking for ShairportQt devices...");
                Console.WriteLine("Please make sure ShairportQt is running on the network");
                
                // Prompt the user for the device IP
                Console.Write("Enter ShairportQt device IP address: ");
                string deviceIp = Console.ReadLine();
                
                if (string.IsNullOrEmpty(deviceIp))
                {
                    Console.WriteLine("No device IP provided, using 127.0.0.1");
                    deviceIp = "127.0.0.1";
                }
                
                // Use DNS-SD to discover TXT records for the device
                Console.WriteLine($"Discovering TXT records for {deviceIp}...");
                var txtRecords = await DiscoverTxtRecordsAsync(deviceIp);
                
                if (txtRecords.Count > 0)
                {
                    Console.WriteLine($"Found {txtRecords.Count} TXT records:");
                    foreach (var record in txtRecords)
                    {
                        Console.WriteLine($"  {record.Key} = {record.Value}");
                    }
                    
                    // Create options object from TXT records
                    var options = CreateOptionsFromTxtRecords(txtRecords);
                    
                    // Add the device with discovered options
                    Console.WriteLine($"Adding device at {deviceIp} with discovered options...");
                    var device = airTunes.Add(deviceIp, options);
                    
                    if (device != null)
                    {
                        Console.WriteLine($"Device added with key: {device.Key}");
                        
                        // Wait for device to be ready
                        Console.WriteLine("Waiting for device to be ready...");
                        await Task.Delay(5000);
                        
                        // Set volume
                        Console.WriteLine("Setting volume to 50%...");
                        airTunes.SetVolume(device.Key, 50, (Action<object[]>)((args) => {
                            Console.WriteLine("Volume set successfully");
                        }));
                        
                        await Task.Delay(1000);
                        

                        
                        
                        // Write audio data
                        Console.WriteLine("Writing audio data...");
                        bool writeResult = airTunes.Write(audioData.Take(352 * 4 * 300).ToArray());
                        idx += 300;
                        Console.WriteLine($"Write result: {writeResult}");
                        
                        // Wait a bit
                        Console.WriteLine("Waiting for audio playback...");

                        
                        // Set track info
                        // Console.WriteLine("Setting track info...");
                        airTunes.SetTrackInfo(device.Key, "Track 1: Ew", "Joji", "Nectar", (Action<object[]>)((args) => {
                            Console.WriteLine("Track info set successfully");
                        }));

                        /// Set artwork
                        Console.WriteLine("Setting artwork...");
                        byte[] artwork = System.IO.File.ReadAllBytes("C:\\Users\\vapormusic\\Downloads\\aaaa\\AirTunesSharpTest\\artwork.png");

                        airTunes.SetArtwork(device.Key, artwork, "image/png", (Action<object[]>)((args) => {
                            Console.WriteLine("Artwork set successfully");
                        }));
                        
                        await Task.Delay(1000);
                        
                        // End audio stream
                        // Console.WriteLine("Ending audio stream...");
                        // airTunes.End();
                        
                        // await Task.Delay(1000);
                        
                        // // Stop all devices
                        // Console.WriteLine("Stopping all devices...");
                        // airTunes.StopAll(() => {
                        //     Console.WriteLine("All devices stopped");
                        // });
                        while(true);
                    }
                    else
                    {
                        Console.WriteLine("Failed to add device");
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Lib Error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
            
            // Console.WriteLine("Press any key to exit...");
            // Console.ReadKey();
        }
        
        /// <summary>
        /// Discovers TXT records for a device using DNS-SD
        /// </summary>
        /// <param name="ipAddress">IP address of the device</param>
        /// <returns>Dictionary of TXT records</returns>
        private static async Task<Dictionary<string, string>> DiscoverTxtRecordsAsync(string ipAddress)
        {
            var txtRecords = new Dictionary<string, string>();
            
            try
            {
                // Since we already have the IP address, we'll simulate getting TXT records
                // In a real implementation, we would use DNS-SD to discover the TXT records
                
                // For ShairportQt, we'll add some common TXT records
                Console.WriteLine("Adding common TXT records for ShairportQt...");
                
                txtRecords["vol"] = "50";  // Default volume (0-100)
                txtRecords["tp"] = "UDP";  // Transport protocol
                txtRecords["sm"] = "false"; // Sleep mode
                txtRecords["ek"] = "1";    // Encryption key
                txtRecords["et"] = "0,1";  // Encryption types
                txtRecords["cn"] = "1";    // Audio channels
                txtRecords["ch"] = "2";    // Audio codec
                txtRecords["ss"] = "16";   // Sample size
                txtRecords["sr"] = "44100"; // Sample rate
                txtRecords["pw"] = "false"; // Password protected
                txtRecords["vn"] = "65537"; // Version number
                txtRecords["md"] = "0,1,2"; // Metadata types
                txtRecords["vs"] = "130.14"; // Server version
                txtRecords["am"] = "ShairportQt"; // Device model
                txtRecords["txtvers"] = "1"; // TXT record version
                
                // Add device-specific information
                txtRecords["deviceid"] = "11:22:33:44:55:66"; // Device ID (usually MAC address)
                txtRecords["features"] = "0x5A7FFFF7,0x1E"; // Device features
                
                Console.WriteLine($"Added {txtRecords.Count} simulated TXT records for ShairportQt");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error discovering TXT records: {ex.Message}");
            }
            
            return txtRecords;
        }
        
        /// <summary>
        /// Creates an options object from TXT records
        /// </summary>
        /// <param name="txtRecords">Dictionary of TXT records</param>
        /// <returns>Options object</returns>
        private static ExpandoObject CreateOptionsFromTxtRecords(Dictionary<string, string> txtRecords)
        {
            // Create a dynamic object to hold the options
            var options = new
            {
                // Default volume
                volume = txtRecords.TryGetValue("vol", out var volStr) && int.TryParse(volStr, out var vol) 
                    ? vol 
                    : 50,
                
                // Password if available
                password = txtRecords.TryGetValue("pw", out var pw) 
                    ? pw 
                    : null,
                
                // Other relevant options from TXT records
                deviceId = txtRecords.TryGetValue("deviceid", out var id) 
                    ? id 
                    : null,
                
                model = txtRecords.TryGetValue("am", out var model) 
                    ? model 
                    : null,
                
                features = txtRecords.TryGetValue("features", out var features) 
                    ? features 
                    : null,
                port = 5000
            };

            dynamic expando = new ExpandoObject();
            var expandoDict = (IDictionary<string, object>)expando;

            foreach (var property in options.GetType().GetProperties())
            {
                expandoDict[property.Name] = property.GetValue(options);
            }
            return expando;
        }
    }
}
