using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using AirTunesSharp;

namespace AirTunesSharpTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("AirTunesSharp Test Application");
            Console.WriteLine("------------------------------");

            var running = true;

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
                airTunes.On("device", (eventArgs) =>
                {
                    string key = eventArgs[0].ToString();
                    string status = eventArgs[1].ToString();
                    string desc = eventArgs.Length > 2 ? eventArgs[2]?.ToString() : null;

                    Console.WriteLine($"Device event: {key} - {status} {(desc != null ? $"({desc})" : "")}");
                });

                airTunes.On("buffer", (eventArgs) =>
                {
                    Console.WriteLine($"Buffer event: {eventArgs[0]}");
                });

                airTunes.On("drain", (eventArgs) =>
                {
                    // Write more audio data
                    Console.WriteLine("Writing more audio data...");
                    airTunes.Write(audioData.Skip(352 * 4 * idx).Take(352 * 4 * 300).ToArray());
                    idx += 300;
                    // Check if we have reached the end of the audio data
                    if (idx >= audioData.Length / (352 * 4))
                    {
                        Console.WriteLine("End of audio data reached, ending stream...");
                        airTunes.End();
                        running = false;
                    }

                });

                airTunes.On("error", (eventArgs) =>
                {
                    Console.WriteLine($"Error event: {eventArgs[0]}");
                });

                Console.WriteLine("Event handlers registered");
                Console.WriteLine("------------------------------");
                Console.WriteLine("Scanning for devices...");
                var deviceScanner = new AirTunesSharp.Utils.DeviceScanner();
                deviceScanner.StartScanning();
                await Task.Delay(5000);
                deviceScanner.StopScanning();
                Console.WriteLine("Scanning complete");
                var devices = deviceScanner.GetAirPlayDevices();
                Console.WriteLine($"Found {devices.Count} devices:");
                foreach (var dev in devices)
                {
                    Console.WriteLine($"{dev["name"]} with address {dev["host"]}:{dev["port"]}");
                    Console.WriteLine($"Txt records: {string.Join(", ", dev["txt"])}");
                }

                if (devices.Count == 0)
                {
                    Console.WriteLine("No devices found, exiting...");
                    running = false;
                    return;
                }

                // Prompt the user for the device IP
                Console.Write("Enter AirPlay device IP address: ");
                string deviceIp = Console.ReadLine();

                if (string.IsNullOrEmpty(deviceIp))
                {
                    Console.WriteLine("No device IP provided, using first device found");
                    deviceIp = devices[0]["host"];
                }

                // Get TXT records for the device 
                Console.WriteLine("Discovering TXT records for the device...");

                var txtRecords = devices.Find(d => d["host"] == deviceIp.Trim())["txt"];
                var deviceOptions = devices.Find(d => d["host"] == deviceIp.Trim())["options"];
                Console.WriteLine($"Device options: {deviceOptions}");

                // Check if device requires password
                string password = null;
                if (deviceOptions != null && deviceOptions["needPassword"])
                {
                    Console.WriteLine("Device requires password, enter password: ");
                    deviceOptions["password"] = Console.ReadLine();
                    
                }


                // Create options object from TXT records
                dynamic expando = new ExpandoObject();
                var expandoDict = (IDictionary<string, object>)expando;
                expandoDict["host"] = deviceIp;
                expandoDict["volume"] = 50;
                expandoDict["port"] = Int32.Parse(devices.Find(d => d["host"] == deviceIp.Trim())["port"]);

                foreach (var kvp in deviceOptions){
                    expandoDict.Add(kvp.Key, kvp.Value);
                }

                // Add the device with discovered options
                Console.WriteLine($"Adding device at {deviceIp} with discovered options...");
                var device = airTunes.Add(deviceIp, expando);

                if (device != null)
                {
                    Console.WriteLine($"Device added with key: {device.Key}");

                    // Wait for device to be ready
                    Console.WriteLine("Waiting for device to be ready...");
                    await Task.Delay(5000);

                    // Set volume
                    Console.WriteLine("Setting volume to 50%...");
                    airTunes.SetVolume(device.Key, 50, (Action<object[]>)((args) =>
                    {
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
                    airTunes.SetTrackInfo(device.Key, "Track 1: Ew", "Joji", "Nectar", (Action<object[]>)((args) =>
                    {
                        Console.WriteLine("Track info set successfully");
                    }));

                    /// Set artwork
                    Console.WriteLine("Setting artwork...");
                    byte[] artwork = System.IO.File.ReadAllBytes("C:\\Users\\vapormusic\\Downloads\\aaaa\\AirTunesSharpTest\\artwork.png");

                    airTunes.SetArtwork(device.Key, artwork, "image/png", (Action<object[]>)((args) =>
                    {
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
                    while (running) ;
                }
                else
                {
                    Console.WriteLine("Failed to add device");
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Lib Error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
    }
}
