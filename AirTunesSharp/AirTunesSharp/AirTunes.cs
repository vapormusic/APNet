using System;
using System.IO;

namespace AirTunesSharp
{
    /// <summary>
    /// C# equivalent of index.js
    /// Main AirTunes class that provides the public API
    /// </summary>
    public class AirTunes : EventEmitter
    {
        private readonly Audio.AudioOut _audioOut;
        private readonly Devices.Devices _devices;
        private readonly Audio.CircularBuffer _circularBuffer;

        /// <summary>
        /// Initializes a new instance of the AirTunes class
        /// </summary>
        public AirTunes()
        {
            _audioOut = new Audio.AudioOut();
            _devices = new Devices.Devices(_audioOut);

            _devices.Init();
            _devices.On("status", args =>
            {
                string key = args[0].ToString();
                string status = args[1].ToString();
                string desc = args.Length > 2 ? args[2].ToString() : null;
                Emit("device", key, status, desc);
            });

            _circularBuffer = new Audio.CircularBuffer(Config.PacketsInBuffer, Config.PacketSize);

            _circularBuffer.On("status", args =>
            {
                Emit("buffer", args[0]);
            });

            _audioOut.Init(_devices, _circularBuffer);

            _circularBuffer.On("drain", args =>
            {
                Emit("drain");
            });

            _circularBuffer.On("error", args =>
            {
                Emit("error", args[0]);
            });
        }

        /// <summary>
        /// Adds an AirTunes device
        /// </summary>
        /// <param name="host">Host address</param>
        /// <param name="options">Device options</param>
        /// <returns>The added device</returns>
        public dynamic Add(string host, dynamic options)
        {
            return _devices.Add("airtunes", host, options);
        }

        /// <summary>
        /// Adds a CoreAudio device
        /// </summary>
        /// <param name="options">Device options</param>
        /// <returns>The added device</returns>
        public dynamic AddCoreAudio(dynamic options)
        {
            return _devices.Add("coreaudio", null, options);
        }

        /// <summary>
        /// Stops all devices
        /// </summary>
        /// <param name="callback">Callback function</param>
        public void StopAll(Action callback)
        {
            _devices.StopAll(callback);
        }

        /// <summary>
        /// Sets the volume for a device
        /// </summary>
        /// <param name="deviceKey">Device key</param>
        /// <param name="volume">Volume level</param>
        /// <param name="callback">Callback function</param>
        public void SetVolume(string deviceKey, int volume, Action<object[]> callback)
        {
            _devices.SetVolume(deviceKey, volume, callback);
        }

        /// <summary>
        /// Sets track information for a device
        /// </summary>
        /// <param name="deviceKey">Device key</param>
        /// <param name="name">Track name</param>
        /// <param name="artist">Artist name</param>
        /// <param name="album">Album name</param>
        /// <param name="callback">Callback function</param>
        public void SetTrackInfo(string deviceKey, string name, string artist, string album, Action<object[]> callback)
        {
            _devices.SetTrackInfo(deviceKey, name, artist, album, callback);
        }

        /// <summary>
        /// Resets the circular buffer
        /// </summary>
        public void Reset()
        {
            _circularBuffer.Reset();
        }

        /// <summary>
        /// Sets artwork for a device
        /// </summary>
        /// <param name="deviceKey">Device key</param>
        /// <param name="art">Artwork data</param>
        /// <param name="contentType">Content type</param>
        /// <param name="callback">Callback function</param>
        public void SetArtwork(string deviceKey, byte[] art, string contentType, Action<object[]> callback)
        {
            _devices.SetArtwork(deviceKey, art, contentType, callback);
        }

        /// <summary>
        /// Sets the passcode for a device
        /// </summary>
        /// <param name="deviceKey">Device key</param>
        /// <param name="passcode">Passcode</param>
        public void SetPasscode(string deviceKey, string passcode)
        {
            _devices.SetPasscode(deviceKey, passcode);
        }



        /// <summary>
        /// Writes audio data to the buffer
        /// </summary>
        /// <param name="data">Audio data</param>
        /// <returns>True if more data can be written, false if buffer is full</returns>
        public bool Write(byte[] data)
        {
            return _circularBuffer.Write(data);
        }

        /// <summary>
        /// Signals the end of audio data
        /// </summary>
        public void End()
        {
            _circularBuffer.End();
        }
    }
}
