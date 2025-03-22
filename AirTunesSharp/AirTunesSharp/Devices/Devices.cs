using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AirTunesSharp.Devices
{
    /// <summary>
    /// C# equivalent of devices.js
    /// Manages collection of AirTunes devices
    /// </summary>
    public class Devices : EventEmitter
    {
        private readonly Audio.AudioOut _audioOut;
        private readonly Dictionary<string, AirTunesDevice> _devices = new Dictionary<string, AirTunesDevice>();
        private bool _hasAirTunes = false;

        /// <summary>
        /// Initializes a new instance of the Devices class
        /// </summary>
        /// <param name="audioOut">Audio output manager</param>
        public Devices(Audio.AudioOut audioOut)
        {
            _audioOut = audioOut;
        }

        /// <summary>
        /// Initializes the devices manager
        /// </summary>
        public void Init()
        {
            _audioOut.On("need_sync", args =>
            {
                // Relay to all devices
                ForEach(dev =>
                {
                    if (dev is AirTunesDevice airTunesDevice && airTunesDevice.ControlPort != null)
                        airTunesDevice.OnSyncNeeded((int)args[0]);
                });
            });
        }

        /// <summary>
        /// Executes an action for each device
        /// </summary>
        /// <param name="action">Action to execute</param>
        public void ForEach(Action<dynamic> action)
        {
            foreach (var device in _devices.Values)
            {
                action(device);
            }
        }

        /// <summary>
        /// Adds a device
        /// </summary>
        /// <param name="type">Device type</param>
        /// <param name="host">Host address</param>
        /// <param name="options">Device options</param>
        /// <returns>The added device</returns>
        public dynamic Add(string type, string host, dynamic options)
        {
            options = options ?? new { };

            var dev = new AirTunesDevice(host, _audioOut, options);

            var previousDev = _devices.ContainsKey(dev.Key) ? _devices[dev.Key] : null;

            if (previousDev != null)
            {
                // If device is already in the pool, just report its existing status
                previousDev.ReportStatus();
                return previousDev;
            }

            _devices[dev.Key] = dev;

            dev.On("status", args =>
            {
                string status = args[0].ToString();
                object arg = args.Length > 1 ? args[1] : null;

                if (status == "error" || status == "stopped")
                {
                    _devices.Remove(dev.Key);
                    CheckAirTunesDevices();
                }

                if (_hasAirTunes && status == "playing")
                {
                    Emit("need_sync");
                }
            });

            dev.Start();
            CheckAirTunesDevices();

            return dev;
        }

        /// <summary>
        /// Sets the volume for a device
        /// </summary>
        /// <param name="key">Device key</param>
        /// <param name="volume">Volume level</param>
        /// <param name="callback">Callback function</param>
        public void SetVolume(string key, int volume, Action<object[]> callback)
        {
            if (!_devices.TryGetValue(key, out var dev))
            {
                Emit("status", key, "error", "not_found");
                return;
            }

            dev.SetVolume(volume, callback);
        }

        /// <summary>
        /// Sets track information for a device
        /// </summary>
        /// <param name="key">Device key</param>
        /// <param name="name">Track name</param>
        /// <param name="artist">Artist name</param>
        /// <param name="album">Album name</param>
        /// <param name="callback">Callback function</param>
        public void SetTrackInfo(string key, string name, string artist, string album, Action<object[]> callback)
        {
            if (!_devices.TryGetValue(key, out var dev))
            {
                Emit("status", key, "error", "not_found");
                return;
            }

            dev.SetTrackInfo(name, artist, album, callback);
        }

        /// <summary>
        /// Sets artwork for a device
        /// </summary>
        /// <param name="key">Device key</param>
        /// <param name="art">Artwork data</param>
        /// <param name="contentType">Content type</param>
        /// <param name="callback">Callback function</param>
        public void SetArtwork(string key, byte[] art, string contentType, Action<object[]> callback)
        {
            if (!_devices.TryGetValue(key, out var dev))
            {
                Emit("status", key, "error", "not_found");
                return;
            }

            dev.SetArtwork(art, contentType, callback);
        }

        /// <summary>
        /// Stops all devices
        /// </summary>
        /// <param name="allCb">Callback function</param>
        public void StopAll(Action allCb)
        {
            var devices = new List<AirTunesDevice>(_devices.Values);
            int remaining = devices.Count;

            if (remaining == 0)
            {
                allCb();
                return;
            }

            foreach (var dev in devices)
            {
                dev.Stop(() =>
                {
                    remaining--;
                    if (remaining == 0)
                    {
                        _devices.Clear();
                        allCb();
                    }
                });
            }
        }

        /// <summary>
        /// Checks for AirTunes devices
        /// </summary>
        private void CheckAirTunesDevices()
        {
            bool newHasAirTunes = false;

            foreach (var device in _devices.Values)
            {
                if (device.Type == "airtunes")
                {
                    newHasAirTunes = true;
                    break;
                }
            }

            if (newHasAirTunes != _hasAirTunes)
            {
                Emit("airtunes_devices", newHasAirTunes);

                ForEach(dev =>
                {
                    if (dev.GetType().GetMethod("SetHasAirTunes") != null)
                        dev.SetHasAirTunes(newHasAirTunes);
                });
            }

            _hasAirTunes = newHasAirTunes;
        }
    }
}
