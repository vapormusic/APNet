using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using AirTunesSharp.Utils;

namespace AirTunesSharp.Network
{
    /// <summary>
    /// C# equivalent of rtsp.js
    /// Handles RTSP protocol communication for AirTunes
    /// </summary>
    public class RtspClient : EventEmitter
    {
        // Status constants
        private const int OPTIONS = 0;
        private const int ANNOUNCE = 1;
        private const int SETUP = 2;
        private const int RECORD = 3;
        private const int SETVOLUME = 4;
        private const int PLAYING = 5;
        private const int TEARDOWN = 6;
        private const int CLOSED = 7;
        private const int SETDAAP = 8;
        private const int SETART = 9;
        private const int HEARTBEAT = 99;

        private readonly Audio.AudioOut _audioOut;
        private int _status;
        private TcpClient? _socket;
        private int _cseq;
        private string? _announceId;
        private int _activeRemote;
        private string _dacpId;
        private string? _session;
        private System.Timers.Timer? _timeout;
        private int _volume;
        private string? _password;
        private bool _passwordTried;
        private bool _requireEncryption;
        private TrackInfo? _trackInfo;
        private byte[]? _artwork;
        private string? _artworkContentType;
        private Action<object[]>? _callback;
        private int? _controlPort;
        private int? _timingPort;

        private int? _serverPort;
        private System.Timers.Timer? _heartBeat;

        /// <summary>
        /// Initializes a new instance of the RtspClient class
        /// </summary>
        /// <param name="volume">Initial volume</param>
        /// <param name="password">Password for authentication</param>
        /// <param name="audioOut">Audio output manager</param>
        public RtspClient(int volume, string? password, Audio.AudioOut audioOut)
        {
            _audioOut = audioOut;
            _status = OPTIONS;
            _socket = null;
            _cseq = 0;
            _announceId = null;
            _activeRemote = NumUtil.RandomInt(9);
            _dacpId = NumUtil.RandomHex(8);
            _session = null;
            _timeout = null;
            _volume = volume;
            _password = password;
            _passwordTried = false;
            _requireEncryption = false;
            _trackInfo = null;
            _artwork = null;
            _artworkContentType = null;
            _callback = null;
            _controlPort = null;
            _timingPort = null;
            _heartBeat = null;
        }

        /// <summary>
        /// Starts the RTSP handshake process
        /// </summary>
        /// <param name="udpServers">UDP servers for control and timing</param>
        /// <param name="host">Target host</param>
        /// <param name="port">Target port</param>
        public void StartHandshake(UdpServers udpServers, string host, int port)
        {
            StartTimeout();

            _controlPort = udpServers.Control.Port;
            _timingPort = udpServers.Timing.Port;

            _socket = new TcpClient();
            
            try
            {
                _socket.ConnectAsync(host, port).ContinueWith(t => 
                {
                    if (t.IsFaulted)
                    {
                        Cleanup("connection_refused");
                        return;
                    }

                    ClearTimeout();
                    SendNextRequest();
                    StartHeartBeat();
                });

                NetworkStream stream = _socket.GetStream();
                byte[] buffer = new byte[4096];
                StringBuilder blob = new StringBuilder();

                Task.Run(async () => 
                {
                    try
                    {
                        while (_socket != null && _socket.Connected)
                        {
                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                            if (bytesRead <= 0)
                            {
                                Cleanup("disconnected");
                                break;
                            }

                            ClearTimeout();

                            string data = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                            blob.Append(data);

                            int endIndex = blob.ToString().IndexOf("\r\n\r\n");
                            if (endIndex < 0)
                                continue;

                            endIndex += 4;
                            string response = blob.ToString().Substring(0, endIndex);
                            ProcessData(response);

                            blob.Clear();
                            if (endIndex < data.Length)
                                blob.Append(data.Substring(endIndex));
                        }
                    }
                    catch (Exception ex)
                    {
                        if (_socket != null)
                        {
                            _socket = null;
                            Cleanup("rtsp_socket", ex.Message);
                        }
                    }
                });
            }
            catch (Exception)
            {
                Cleanup("connection_refused");
            }
        }

        /// <summary>
        /// Starts the timeout timer
        /// </summary>
        private void StartTimeout()
        {
            _timeout = new System.Timers.Timer(Config.RtspTimeout);
            _timeout.Elapsed += (sender, e) => Cleanup("timeout");
            _timeout.AutoReset = false;
            _timeout.Start();
        }

        /// <summary>
        /// Clears the timeout timer
        /// </summary>
        private void ClearTimeout()
        {
            if (_timeout != null)
            {
                _timeout.Stop();
                _timeout.Dispose();
                _timeout = null;
            }
        }

        /// <summary>
        /// Initiates teardown of the RTSP connection
        /// </summary>
        public void Teardown()
        {
            if (_status == CLOSED)
            {
                Emit("end", "stopped");
                return;
            }

            _status = TEARDOWN;
            SendNextRequest();
        }

        /// <summary>
        /// Sets the volume level
        /// </summary>
        /// <param name="volume">Volume level (0-100)</param>
        /// <param name="callback">Callback function</param>
        public void SetVolume(int volume, Action<object[]> callback)
        {
            if (_status != PLAYING)
                return;

            _volume = volume;
            _callback = callback;
            _status = SETVOLUME;
            SendNextRequest();
        }

        /// <summary>
        /// Starts the heartbeat timer
        /// </summary>
        private void StartHeartBeat()
        {
            if (Config.RtspHeartbeat > 0)
            {
                _heartBeat = new System.Timers.Timer(Config.RtspHeartbeat);
                _heartBeat.Elapsed += (sender, e) => SendHeartBeat(args => { });
                _heartBeat.AutoReset = true;
                _heartBeat.Start();
            }
        }

        /// <summary>
        /// Sends a heartbeat message
        /// </summary>
        /// <param name="callback">Callback function</param>
        private void SendHeartBeat(Action<object[]> callback)
        {
            if (_status != PLAYING)
                return;

            _status = HEARTBEAT;
            _callback = callback;
            SendNextRequest();
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
            if (_status != PLAYING)
                return;

            _trackInfo = new TrackInfo
            {
                Name = name,
                Artist = artist,
                Album = album
            };
            _status = SETDAAP;
            _callback = callback;
            SendNextRequest();
        }

        /// <summary>
        /// Sets artwork for the current track
        /// </summary>
        /// <param name="art">Artwork data or file path</param>
        /// <param name="contentType">Content type of the artwork</param>
        /// <param name="callback">Callback function</param>
        public void SetArtwork(byte[] art, string? contentType, Action<object[]> callback)
        {
            if (_status != PLAYING)
                return;

            if (contentType == null)
                return;

            _artworkContentType = contentType;
            _artwork = art;
            _status = SETART;
            _callback = callback;
            SendNextRequest();
        }

        /// <summary>
        /// Increments and returns the next CSeq value
        /// </summary>
        /// <returns>Next CSeq value</returns>
        private int NextCSeq()
        {
            _cseq += 1;
            return _cseq;
        }

        /// <summary>
        /// Cleans up resources and emits end event
        /// </summary>
        /// <param name="type">End type</param>
        /// <param name="msg">Optional message</param>
        public void Cleanup(string type, string? msg = null)
        {
            Emit("end", type, msg);
            _status = CLOSED;
            _trackInfo = null;
            _artwork = null;
            _artworkContentType = null;
            _callback = null;
            RemoveAllListeners();

            if (_timeout != null)
            {
                _timeout.Stop();
                _timeout.Dispose();
                _timeout = null;
            }

            if (_heartBeat != null)
            {
                _heartBeat.Stop();
                _heartBeat.Dispose();
                _heartBeat = null;
            }

            if (_socket != null)
            {
                _socket.Close();
                _socket = null;
            }
        }

        /// <summary>
        /// Processes RTSP response data
        /// </summary>
        /// <param name="blob">Response data</param>
        private void ProcessData(string blob)
        {
            RtspResponse response = RtspResponse.ParseResponse(blob);
            Console.WriteLine($"Resp status: {_status} {response.Code} {response.Status}");
            Console.WriteLine($"Headers: {response.Headers}");
            Console.WriteLine($"Body: {response.Body}");

            if (response.Code >= 400 & response.Code != 416)
            {
                if (response.Code == 401 && !_passwordTried && _password != null)
                {
                    _passwordTried = true;
                    
                    // Extract digest auth parameters
                    string authHeader = response.Headers.ContainsKey("WWW-Authenticate") 
                        ? response.Headers["WWW-Authenticate"] 
                        : null;
                    
                    if (authHeader != null && authHeader.StartsWith("Digest"))
                    {
                        var digestInfo = ParseDigestAuth(authHeader);
                        digestInfo["username"] = "iTunes";
                        digestInfo["password"] = _password;
                        
                        SendNextRequest(digestInfo);
                        return;
                    }
                }
                
                Cleanup("rtsp_error", response.Status);
                return;
            }

            if (_callback != null)
            {
                var cb = _callback;
                _callback = null;
                cb(new object[] { });
            }

            switch (_status)
            {
                case HEARTBEAT:
                    _status = PLAYING;
                break;
                case OPTIONS:
                    if(response.Headers.ContainsKey("Apple-Response"))
                        _requireEncryption = true;
                    _status = ANNOUNCE;
                    break;             
                case ANNOUNCE:
                    _status = SETUP;
                    break;
                    
                case SETUP:

                    if (response.Headers.ContainsKey("Session"))
                        _session = response.Headers["Session"].Split(';')[0];

                    /// Parse the ports from the response
                    if (response.Headers.ContainsKey("Transport"))
                    {
                        string transport = response.Headers["Transport"];
                        string[] parts = transport.Split(';');
                        foreach (var part in parts)
                        {
                            string[] kv = part.Split('=');
                            if (kv.Length == 2)
                            {
                                if (kv[0] == "control_port")
                                    _controlPort = int.Parse(kv[1]);
                                else if (kv[0] == "timing_port")
                                    _timingPort = int.Parse(kv[1]);
                                else if (kv[0] == "server_port")
                                    _serverPort = int.Parse(kv[1]);
                            }
                        }
                    }

                    Console.WriteLine("New ports: " + _controlPort + " " + _timingPort + " " + _serverPort);
                    
                    Emit("config", new
                    {
                        audioLatency = 0,
                        requireEncryption = _requireEncryption,
                        server_port = _serverPort,
                        control_port = _controlPort,
                        timing_port = _timingPort
                    });
                    _status = RECORD;
                    break;
                    
                case RECORD:
                    _status = PLAYING;
                    Emit("ready");
                    break;
                    
                case SETVOLUME:
                case SETDAAP:
                case SETART:
                    _status = PLAYING;
                    break;
                    
                case TEARDOWN:
                    Cleanup("stopped");
                    break;
            }

            SendNextRequest();
        }

        /// <summary>
        /// Parses a digest authentication header
        /// </summary>
        /// <param name="authHeader">Authentication header</param>
        /// <returns>Dictionary of digest parameters</returns>
        private Dictionary<string, string> ParseDigestAuth(string authHeader)
        {
            var result = new Dictionary<string, string>();
            string[] parts = authHeader.Substring(7).Split(',');
            
            foreach (var part in parts)
            {
                int equalsPos = part.IndexOf('=');
                if (equalsPos > 0)
                {
                    string key = part.Substring(0, equalsPos).Trim();
                    string value = part.Substring(equalsPos + 1).Trim();
                    
                    // Remove quotes if present
                    if (value.StartsWith("\"") && value.EndsWith("\""))
                        value = value.Substring(1, value.Length - 2);
                        
                    result[key] = value;
                }
            }
            
            return result;
        }

        /// <summary>
        /// Creates an RTSP request header
        /// </summary>
        /// <param name="method">RTSP method</param>
        /// <param name="uri">Request URI</param>
        /// <param name="digestInfo">Optional digest authentication info</param>
        /// <returns>RTSP header string</returns>
        private string MakeHead(string method, string uri, Dictionary<string, string>? digestInfo = null)
        {
            string head = $"{method} {uri} RTSP/1.0\r\n" +
                $"CSeq: {NextCSeq()}\r\n" +
                $"User-Agent: {Config.UserAgent}\r\n" +
                $"DACP-ID: {_dacpId.ToUpper()}\r\n" +
                $"Client-Instance: {_dacpId.ToUpper()}\r\n" +
                (_session != null ? $"Session: {_session}\r\n" : "") +
                $"Active-Remote: {_activeRemote}\r\n";

            if (digestInfo != null)
            {
                string username = digestInfo["username"];
                string realm = digestInfo["realm"];
                string password = digestInfo["password"];
                string nonce = digestInfo["nonce"];
                
                string ha1 = Md5($"{username}:{realm}:{password}");
                string ha2 = Md5($"{method}:{uri}");
                string diResponse = Md5($"{ha1}:{nonce}:{ha2}");

                head += $"Authorization: Digest " +
                    $"username=\"{username}\", " +
                    $"realm=\"{realm}\", " +
                    $"nonce=\"{nonce}\", " +
                    $"uri=\"{uri}\", " +
                    $"response=\"{diResponse}\"\r\n";
            }

            return head;
        }

        /// <summary>
        /// Creates an RTSP request header with URL
        /// </summary>
        /// <param name="method">RTSP method</param>
        /// <param name="digestInfo">Optional digest authentication info</param>
        /// <returns>RTSP header string</returns>
        private string MakeHeadWithURL(string method, Dictionary<string, string>? digestInfo = null)
        {
            if (_socket == null)
                throw new InvalidOperationException("Socket is not connected");
                
            IPEndPoint localEndPoint = (IPEndPoint)_socket.Client.LocalEndPoint;
            // Get ipv4 address


            string uri = $"rtsp://{localEndPoint.Address.MapToIPv4()}/{_announceId}";
            return MakeHead(method, uri, digestInfo);
        }

        
        public byte[] DaapEncodeList(string field, params byte[][] values)
        {
            byte[] value = ConcatArrays(values);
            byte[] buf = new byte[field.Length + 4];
            Encoding.ASCII.GetBytes(field).CopyTo(buf, 0);
            BitConverter.GetBytes((uint)value.Length).CopyTo(buf, field.Length);
            Array.Reverse(buf, field.Length, 4); // Ensure big-endian order
            
            return ConcatArrays(buf, value);
        }

        public byte[] DaapEncode(string field, string value)
        {
            byte[] valueBytes = Encoding.ASCII.GetBytes(value);
            byte[] buf = new byte[field.Length + valueBytes.Length + 4];
            Encoding.ASCII.GetBytes(field).CopyTo(buf, 0);
            BitConverter.GetBytes((uint)valueBytes.Length).CopyTo(buf, field.Length);
            Array.Reverse(buf, field.Length, 4); // Ensure big-endian order
            valueBytes.CopyTo(buf, field.Length + 4);
            
            return buf;
        }

        private byte[] ConcatArrays(params byte[][] arrays)
        {
            int length = 0;
            foreach (var arr in arrays) length += arr.Length;
            
            byte[] result = new byte[length];
            int offset = 0;
            foreach (var arr in arrays)
            {
                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }
            
            return result;
        }

        /// <summary>
        /// Creates RTP info header
        /// </summary>
        /// <returns>RTP info header string</returns>
        private string MakeRtpInfo()
        {
            int nextSeq = _audioOut.LastSeq + 1;
            uint rtpSyncTime = (uint)(nextSeq * Config.FramesPerPacket + 2 * (uint)Config.SamplingRate);
            return $"RTP-Info: seq={nextSeq};rtptime={rtpSyncTime}\r\n";
        }

        /// <summary>
        /// Sends the next RTSP request based on current status
        /// </summary>
        /// <param name="digestInfo">Optional digest authentication info</param>
        private void SendNextRequest(Dictionary<string, string>? digestInfo = null)
        {
            string request = "";
            string body = "";
            
            Console.WriteLine($"Sending request: {_status}");

            switch (_status)
            {
                case HEARTBEAT:
                case OPTIONS:
                    request += MakeHead("OPTIONS", "*", digestInfo);
                    request += "Apple-Challenge: SdX9kFJVxgKVMFof/Znj4Q\r\n\r\n";
                    break;

                case ANNOUNCE:
                    _announceId = NumUtil.RandomInt(8).ToString();
                    
                    if (_socket == null)
                        throw new InvalidOperationException("Socket is not connected");
                        
                    IPEndPoint localEndPoint = (IPEndPoint)_socket.Client.LocalEndPoint;
                    
                    body =
                        "v=0\r\n" +
                        $"o=iTunes {_announceId} 0 IN IP4 {localEndPoint.Address.MapToIPv4()}\r\n" +
                        "s=iTunes\r\n" +
                        $"c=IN IP4 {localEndPoint.Address.MapToIPv4()}\r\n" +
                        "t=0 0\r\n" +
                        "m=audio 0 RTP/AVP 96\r\n" +
                        "a=rtpmap:96 AppleLossless\r\n" +
                        "a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n";
                        
                    if (_requireEncryption)
                    {
                        body +=
                            $"a=rsaaeskey:{Config.RsaAeskeyBase64}\r\n" +
                            $"a=aesiv:{Config.IvBase64}\r\n";
                    }

                    request += MakeHeadWithURL("ANNOUNCE", digestInfo);
                    request +=
                        "Content-Type: application/sdp\r\n" +
                        $"Content-Length: {body.Length}\r\n\r\n";
                    break;

                case SETUP:
                    request += MakeHeadWithURL("SETUP", digestInfo);
                    request +=
                        "Transport: RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;" +
                        $"control_port={_controlPort};timing_port={_timingPort}\r\n\r\n";
                    break;

                case RECORD:
                    request += MakeHeadWithURL("RECORD", digestInfo);
                    request += MakeRtpInfo();
                    request += "Range: npt=0-\r\n\r\n";
                    break;

                case SETVOLUME:
                    double attenuation = 0;
                    if (_volume == 0) {
                        attenuation = 144.0;
                    }
                    else {
                        attenuation = (-30.0) * (100.0 - (_volume)) / 100.0;
                    }

                    request += MakeHeadWithURL("SET_PARAMETER", digestInfo);
                    request += "Content-Type: text/parameters\r\n";
                    body = $"volume: {attenuation :F6}\r\n";
                    request += $"Content-Length: {body.Length}\r\n\r\n";
                    break;

                case TEARDOWN:
                    request += MakeHeadWithURL("TEARDOWN", digestInfo);
                    request += "\r\n";
                    break;

                case SETDAAP:
                    if (_trackInfo == null)
                        return;
                        
                    request += MakeHeadWithURL("SET_PARAMETER", digestInfo);
                    request += "Content-Type: application/x-dmap-tagged\r\n";
                    
                    // Create DAAP body - this would need a proper DAAP implementation
                    // For now, we'll use a placeholder
                    body = "DAAP data would go here";
                    
                    request += $"Content-Length: {body.Length}\r\n\r\n";
                    break;

                case SETART:
                    if (_artwork == null || _artworkContentType == null)
                        return;
                        
                    request += MakeHeadWithURL("SET_PARAMETER", digestInfo);
                    request += $"Content-Type: {_artworkContentType}\r\n";
                    body = Convert.ToBase64String(_artwork);
                    request += $"Content-Length: {_artwork.Length}\r\n\r\n";
                    break;
            }

            if (request.Length > 0 && _socket != null)
            {
                try
                {
                    byte[] requestBytes = Encoding.ASCII.GetBytes(request + body);
                    NetworkStream stream = _socket.GetStream();
                    stream.Write(requestBytes, 0, requestBytes.Length);
                    StartTimeout();
                }
                catch (Exception)
                {
                    Cleanup("socket_error");
                }
            }

            Console.WriteLine($"Sending request: {request + body}");
        }

        /// <summary>
        /// Calculates MD5 hash of a string
        /// </summary>
        /// <param name="input">Input string</param>
        /// <returns>MD5 hash as uppercase hex string</returns>
        private string Md5(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }
    }

    /// <summary>
    /// Represents an RTSP response
    /// </summary>
    public class RtspResponse
    {
        public int Code { get; set; }
        public string Status { get; set; } = string.Empty;
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();

        public string Body { get; set; } = string.Empty;
        
        /// <summary>
        /// Parses an RTSP response
        /// </summary>
        /// <param name="blob">Response data</param>
        /// <returns>Parsed response</returns>
        public static RtspResponse ParseResponse(string blob)
        {
            var response = new RtspResponse
            {
                Headers = new Dictionary<string, string>()
            };
            
            string[] lines = blob.Split(new[] { "\r\n" }, StringSplitOptions.None);
            
            // Parse status line
            var codeRes = System.Text.RegularExpressions.Regex.Match(lines[0], @"(\w+)\/(\S+) (\d+) (.*)");
            if (!codeRes.Success)
            {
                response.Code = 599;
                response.Status = "UNEXPECTED " + lines[0];
                return response;
            }
            
            response.Code = int.Parse(codeRes.Groups[3].Value);
            response.Status = codeRes.Groups[4].Value;
            
            // Parse headers
            for (int i = 1; i < lines.Length; i++)
            {
                if (string.IsNullOrEmpty(lines[i]))
                    continue;
                    
                var headerMatch = System.Text.RegularExpressions.Regex.Match(lines[i], @"([^:]+):\s*(.*)");
                if (headerMatch.Success)
                {
                    response.Headers[headerMatch.Groups[1].Value] = headerMatch.Groups[2].Value;
                }
            }

            response.Body = string.Join("\r\n", lines, 1, lines.Length - 1);
            
            return response;
        }
    }


    /// <summary>
    /// Track information
    /// </summary>
    public class TrackInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Artist { get; set; } = string.Empty;
        public string Album { get; set; } = string.Empty;
    }
}
