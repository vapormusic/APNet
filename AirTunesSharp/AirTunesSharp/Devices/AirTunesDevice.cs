using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Policy;
using AirTunesSharp.Network;
using AirTunesSharp.Utils;
using AirTunesSharp.Utils.HomeKit;

namespace AirTunesSharp.Devices
{
    /// <summary>
    /// C# equivalent of device_airtunes.js
    /// Represents an AirTunes device for audio streaming
    /// </summary>
    public class AirTunesDevice : EventEmitter
    {
        private const int RTP_HEADER_SIZE = 12;

        private readonly UdpServers _udpServers;
        private readonly Audio.AudioOut _audioOut;
        private readonly string _host;
        private readonly int _port;
        private readonly RtspClient _rtsp;
        private Action<object[]> _audioCallback;
        private List<object> _encoder = new List<object>();
        private UdpClient _audioSocket;
        private int _audioLatency;
        private bool _requireEncryption;
        private int _serverPort;
        private int _controlPort;
        private int _timingPort;

        private Credentials? _credentials;
        private bool _isAirPlay2 = false;

        /// <summary>
        /// Gets the type of the device
        /// </summary>
        public string Type { get; } = "airtunes";

        /// <summary>
        /// Gets the host of the device
        /// </summary>
        public string Host => _host;

        /// <summary>
        /// Gets the key of the device
        /// </summary>
        public string Key { get; }

        /// <summary>
        /// Gets the status of the device
        /// </summary>
        public string Status { get; private set; }
        
        /// <summary>
        /// Gets the control port of the device
        /// </summary>
        public int ControlPort => _controlPort;

        /// <summary>
        /// Initializes a new instance of the AirTunesDevice class
        /// </summary>
        /// <param name="host">Host address</param>
        /// <param name="audioOut">Audio output manager</param>
        /// <param name="options">Device options</param>
        public AirTunesDevice(string host, Audio.AudioOut audioOut, dynamic options)
        {
            if (string.IsNullOrEmpty(host))
                throw new ArgumentException("host is mandatory");

            _udpServers = new UdpServers();
            _audioOut = audioOut;
            _host = host;
            Console.WriteLine($"Adding AirTunes device at {options}");
            _port = options.port ?? 5000;
            Key = $"{_host}:{_port}";
            _rtsp = new RtspClient(options.volume ?? 50, options.password ?? null, audioOut, options);
            _audioCallback = null;
        }

        /// <summary>
        /// Starts the device
        /// </summary>
        public void Start()
        {
            _audioSocket = new UdpClient(AddressFamily.InterNetwork);

            // Wait until timing and control ports are chosen
            _udpServers.Once("ports", args =>
            {
                if (args[0] != null)
                {
                    Status = "stopped";
                    Emit("status", "stopped");
                    Emit("error", "udp_ports", ((Exception)args[0]).Message);
                    return;
                }

                Console.WriteLine("ports args: " + args);

                DoHandshake();
            });

            _udpServers.Bind(_host);


        }

        /// <summary>
        /// Initiates the RTSP handshake
        /// </summary>
        private void DoHandshake()
        {
            _rtsp.On("config", args =>
            {
                dynamic setup = args[0];
                _audioLatency = setup.audioLatency;
                _requireEncryption = setup.requireEncryption;
                _serverPort = setup.server_port;
                _controlPort = setup.control_port;
                _timingPort = setup.timing_port;
                if (setup.credentials != null)
                    _credentials = setup.credentials;
                Console.WriteLine($"Server port: {_serverPort}, Control port: {_controlPort}, Timing port: {_timingPort}");
                // _udpServers.Close();
                
            });

            _rtsp.On("ready", args =>
            {
                RelayAudio();
            });

            _rtsp.On("end", args =>
            {
                string err = args[0].ToString();
                Cleanup();

                if (err != "stopped")
                    Emit(err);
            });

            _rtsp.On("need_password", args => {
                Emit("status","need_password");
            });

           _rtsp.On("pair_success", args => {
                Emit("status","pair_success");
            });


            _rtsp.StartHandshake(_udpServers, _host, _port);
        }

        /// <summary>
        /// Sets up audio relay
        /// </summary>
        private void RelayAudio()
        {
            Status = "ready";
            Emit("status", "ready");

            _audioCallback = args =>
            {
                // Console.WriteLine("Relaying audio packet");
                Audio.Packet packet = (Audio.Packet)args[0];
                byte[] airTunes = MakeAirTunesPacket(packet, _requireEncryption, _credentials);
                _audioSocket.Send(airTunes, airTunes.Length, new IPEndPoint(IPAddress.Parse(_host), _serverPort));
            };

            _audioOut.On("packet", _audioCallback);
        }

        /// <summary>
        /// Handles sync needed event
        /// </summary>
        /// <param name="seq">Sequence number</param>
        public void OnSyncNeeded(int seq)
        {
            _udpServers.SendControlSync(seq, this);
        }

        /// <summary>
        /// Cleans up resources
        /// </summary>
        public void Cleanup()
        {
            _audioSocket = null;
            Status = "stopped";
            Emit("status", "stopped");

            if (_audioCallback != null)
            {
                _audioOut.RemoveListener("packet", _audioCallback);
                _audioCallback = null;
            }

            _udpServers.Close();
            RemoveAllListeners();
        }

        /// <summary>
        /// Reports the current status
        /// </summary>
        public void ReportStatus()
        {
            Emit("status", Status);
        }

        /// <summary>
        /// Stops the device
        /// </summary>
        /// <param name="callback">Callback function</param>
        public void Stop(Action callback = null)
        {
            _rtsp.Once("end", args =>
            {
                callback?.Invoke();
            });

            _rtsp.Teardown();
        }

        /// <summary>
        /// Sets the volume level
        /// </summary>
        /// <param name="volume">Volume level (0-100)</param>
        /// <param name="callback">Callback function</param>
        public void SetVolume(int volume, Action<object[]> callback)
        {
            _rtsp.SetVolume(volume, callback);
        }

        /// <summary>
        /// Sets track information
        /// </summary>
        /// <param name="name">Track name</param>
        /// <param name="artist">Artist name</param>
        /// <param name="album">Album name</param>
        /// <param name="callback">Callback function</param>
        public void SetTrackInfo(string name, string artist, string album, Action<object[]> callback)
        {
            _rtsp.SetTrackInfo(name, artist, album, callback);
        }

        /// <summary>
        /// Sets the progress for a device
        /// </summary>
        /// <param name="deviceKey">Device key</param>
        /// <param name="progress">Progress</param>
        /// <param name="duration">Duration</param>
        /// <param name="callback">Callback function</param>
        public void SetProgress(long progress, long duration, Action<object[]> callback)
        {
            _rtsp.SetProgress(progress, duration, callback);
        }


        /// <summary>
        /// Sets artwork for the current track
        /// </summary>
        /// <param name="art">Artwork data</param>
        /// <param name="contentType">Content type of the artwork</param>
        /// <param name="callback">Callback function</param>
        public void SetArtwork(byte[] art, string contentType, Action<object[]> callback)
        {
            _rtsp.SetArtwork(art, contentType, callback);
        }

        /// <summary>
        /// Sets the passcode for the device
        /// </summary>
        /// <param name="password">Passcode</param>
        public void SetPasscode(string password) {
            _rtsp.SetPasscode(password);
        }

        /// <summary>
        /// Creates an AirTunes packet from a PCM packet
        /// </summary>
        /// <param name="packet">PCM packet</param>
        /// <param name="requireEncryption">Whether encryption is required</param>
        /// <returns>AirTunes packet</returns>
        private byte[] MakeAirTunesPacket(Audio.Packet packet, bool requireEncryption, Credentials? credentials = null)
        {
            byte[] alac = PcmToALAC(packet.Pcm);
            string md5 = NumUtil.ComputeMD5(alac);
            // Console.WriteLine($"MD5 alac: {md5}");

            byte[] airTunes = new byte[alac.Length + RTP_HEADER_SIZE];
            byte[] header = MakeRTPHeader(packet);

            if (requireEncryption && credentials == null)
            {
                alac = AirTunesEncryption.EncryptAES(alac);
            }
            if (credentials != null)
            {
                byte[] pcm = credentials.EncryptAudio(alac, header.Skip(4).Take(8).ToArray(),packet.Seq.Value);
                byte[] airplay = new byte[pcm.Length + RTP_HEADER_SIZE];
                header.CopyTo(airplay, 0);
                pcm.CopyTo(airplay, RTP_HEADER_SIZE);
                return airplay;
            } else {
                Buffer.BlockCopy(header, 0, airTunes, 0, header.Length);
                Buffer.BlockCopy(alac, 0, airTunes, RTP_HEADER_SIZE, alac.Length);
            }
            return airTunes;
        }

        /// <summary>
        /// Converts PCM data to ALAC format
        /// </summary>
        /// <param name="pcmData">PCM data</param>
        /// <returns>ALAC data</returns>
        private byte[] PcmToALAC(byte[] pcmData)
        {
            // Use the AlacEncoder implementation based on the provided C code
            int bsize = 352;
            int frames = 352;

            return Audio.AlacEncoder.PcmToAlac(pcmData, frames, bsize);
        }

        /// <summary>
        /// Creates an RTP header for a packet
        /// </summary>
        /// <param name="packet">Audio packet</param>
        /// <returns>RTP header</returns>
        public byte[] MakeRTPHeader(Audio.Packet packet)
        {
            byte[] header = new byte[RTP_HEADER_SIZE];

            if (packet.Seq == 0)
            {
                header[0] = 0x80;
                header[1] = 0xe0;
            }
            else
            {
                header[0] = 0x80;
                header[1] = 0x60;
            }

            ushort seq = NumUtil.Low16((int)packet.Seq);
            header[2] = (byte)(seq >> 8);
            header[3] = (byte)(seq & 0xFF);

            byte[] timestampBytes = BitConverter.GetBytes(packet.Timestamp);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(timestampBytes);
            Buffer.BlockCopy(timestampBytes, 0, header, 4, 4);

            byte[] magicBytes = BitConverter.GetBytes(Config.DeviceMagic);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(magicBytes);
            Buffer.BlockCopy(magicBytes, 0, header, 8, 4);

            return header;
        }
    }
}
