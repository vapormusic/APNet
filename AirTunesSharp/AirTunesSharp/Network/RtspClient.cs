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

        private const int PAIR_VERIFY_1 = 10,
        PAIR_VERIFY_2 = 11,
        OPTIONS2 = 12,
        AUTH_SETUP = 13,
        PAIR_PIN_START = 14,
        PAIR_PIN_SETUP_1 = 15,
        PAIR_PIN_SETUP_2 = 16,
        PAIR_PIN_SETUP_3 = 17,
        PAIR_SETUP_1 = 18,
        PAIR_SETUP_2 = 19,
        PAIR_SETUP_3 = 20,
        PAIR_VERIFY_HAP_1 = 21,
        PAIR_VERIFY_HAP_2 = 22,
        SETUP_AP2_1 = 23,
        SETUP_AP2_2 = 24,
        SETPEERS = 25,
        FLUSH = 26,
        GETVOLUME = 27,
        SETPROGRESS = 28;

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

        private Dictionary<string, string>? _digestInfo;

        private bool _triedMd5Uppercase = false;

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
            _digestInfo = null;
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
            _socket.ReceiveTimeout = 4000;
            _socket.SendTimeout = 4000;           
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

                                string data = Encoding.UTF8.GetString(buffer, 0, bytesRead);
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
            if ((_status < 2) || ((_status > 10) && (_status < 26)))
            {
               return;         
            }

            _trackInfo = new TrackInfo
            {
                Name = name,
                Artist = artist,
                Album = album
            };
            _status = SETDAAP;
            _callback = callback;
            SendNextRequest(null, SETDAAP);
        }

        /// <summary>
        /// Sets artwork for the current track
        /// </summary>
        /// <param name="art">Artwork data or file path</param>
        /// <param name="contentType">Content type of the artwork</param>
        /// <param name="callback">Callback function</param>
        public void SetArtwork(byte[] art, string? contentType, Action<object[]> callback)
        {
            if ((_status < 2) || ((_status > 10) && (_status < 26))  )
            {
               return;         
            }


            if (contentType == null)
                return;

            _artworkContentType = contentType;
            _artwork = art;
            _status = SETART;
            _callback = callback;
            SendNextRequest(null, SETART);
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
            Console.WriteLine($"Headers: {string.Join(Environment.NewLine, response.Headers)}");
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
                        _digestInfo = ParseDigestAuth(authHeader);
                        _digestInfo["username"] = "iTunes";
                        _digestInfo["password"] = _password;
                        _digestInfo["realm"] = _digestInfo["realm"].Trim('"');
                        _digestInfo["nonce"] = _digestInfo["nonce"].Trim('"');
                        SendNextRequest(_digestInfo);
                       
                        return;
                    }
                }
                if (_status != OPTIONS)
                {
                    Cleanup("rtsp_error", response.Status);
                    return;
                }
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
                    if (_status != SETDAAP && _status != SETART)
                        _status = PLAYING;
                break;
                case OPTIONS:
                    if(response.Headers.ContainsKey("Apple-Response"))
                        _requireEncryption = true;
                    if (response.Code == 401) {
                        _passwordTried = false;
                        _status = OPTIONS2;
                    } else {
                        _status = ANNOUNCE;
                    }
                    break;  
                case OPTIONS2:
                    // if (response.Code == 401) {
                    //     _status = AUTH_SETUP;
                    // } else {
                        _status = ANNOUNCE;
                    // }
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
                    if (_status != SETDAAP && _status != SETART && _status != SETVOLUME)
                        _status = PLAYING;
                    Emit("ready");
                    break;
                    
                case SETVOLUME:
                    if (_status != SETDAAP && _status != SETART)
                        _status = PLAYING;
                    break;
                case SETDAAP:
                    if (_status != SETVOLUME && _status != SETART)
                        _status = PLAYING;
                    break;
                case SETART:
                    if (_status != SETVOLUME && _status != SETDAAP)
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
        private string MakeHead(string method, string uri, Dictionary<string, string>? digestInfo = null, bool md5Uppercase = true)
        {
            string head = $"{method} {uri} RTSP/1.0\r\n" +
                $"CSeq: {NextCSeq()}\r\n" +
                $"User-Agent: {Config.UserAgent}\r\n" +
                $"DACP-ID: {_dacpId.ToUpper()}\r\n" +
                $"Client-Instance: {_dacpId.ToUpper()}\r\n" +
                (_session != null ? $"Session: {_session}\r\n" : "") +
                $"Active-Remote: {_activeRemote}\r\n";

            if (digestInfo != null || _digestInfo != null)
            {
                if (digestInfo == null)
                    digestInfo = _digestInfo;
                string username = digestInfo["username"];
                string realm = digestInfo["realm"];
                string password = digestInfo["password"];
                string nonce = digestInfo["nonce"];
                
                string ha1 = Md5($"{username}:{realm}:{password}", md5Uppercase);
                string ha2 = Md5($"{method}:{uri}", md5Uppercase);
                string diResponse = Md5($"{ha1}:{nonce}:{ha2}", md5Uppercase);

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

        
        public byte[] DaapEncodeList(string field, string encoding = "ascii", params byte[][] values)
        {
            byte[] value = ConcatArrays(values);
            byte[] buf = new byte[field.Length + 4];
            if (encoding == "utf-8") {
                Encoding.UTF8.GetBytes(field).CopyTo(buf, 0);
            }
            else {
                Encoding.ASCII.GetBytes(field).CopyTo(buf, 0);
            }

            BitConverter.GetBytes((uint)value.Length).CopyTo(buf, field.Length);
            Array.Reverse(buf, field.Length, 4); // Ensure big-endian order
            
            return ConcatArrays(buf, value);
        }

        public byte[] DaapEncode(string field, string encoding, string value)
        {
            byte[] valueBytes = Encoding.ASCII.GetBytes(value);
            byte[] buf = new byte[field.Length + valueBytes.Length + 4];
            if (encoding == "utf-8") {
                Encoding.UTF8.GetBytes(field).CopyTo(buf, 0);
            }
            else {
                Encoding.ASCII.GetBytes(field).CopyTo(buf, 0);
            }
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
        private void SendNextRequest(Dictionary<string, string>? digestInfo = null, int? forcedStatus = null)
        {
            string request = "";
            string body_str = "";
            byte[] body = [];

            if (forcedStatus != null)
                _status = forcedStatus.Value ;
            
            
            Console.WriteLine($"Sending request: {_status}");

            switch (forcedStatus ?? _status)
            {
                //  case PAIR_PIN_START:
                //     I = "366B4165DD64AD3A";
                //     P = null;
                //     s = null;
                //     B = null;
                //     a = null;
                //     A = null;
                //     M1 = null;
                //     epk = null;
                //     authTag = null;
                //     _atv_salt = null;
                //     _atv_pub_key = null;
                //     _hap_encrypteddata = null;
                //     seed = null;
                //     pairingId = Guid.NewGuid().ToString();
                //     credentials = null;
                //     verifier_hap_1 = null;
                //     encryptionKey = null;
                //     if (needPin ||airplay2)
                //     {
                //         request = request.Concat(this.makeHead("POST", "/pair-pin-start", null, true)).ToArray();
                //         if (airplay2)
                //         {

                //             u += "User-Agent: AirPlay/409.16\r\n";
                //             u += "Connection: keep-alive\r\n";
                //             u += "CSeq: " + "0" + "\r\n";

                //         }
                //         u += "Content-Length:" + 0 + "\r\n\r\n";
                //         request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                //     } else
                //     {
                //         emitNeedPassword?.Invoke();
                //         this.status = this.airplay2 ? INFO : PAIR_PIN_SETUP_1;
                //     }
                //     break;
                // case PAIR_PIN_SETUP_1:
                //     request = request.Concat(this.makeHead("POST", "/pair-setup-pin", null, true)).ToArray();
                //     u += "Content-Type: application/x-apple-binary-plist\r\n";

                //     using (var memoryStream = new MemoryStream())
                //     {
                //         BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                //         NSDictionary dict = new NSDictionary();
                //         dict.Add("user", "366B4165DD64AD3A");
                //         dict.Add("method", "pin");
                //         bplist.Write(dict);
                //         byte[] bpbuf = memoryStream.ToArray();

                //         u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                //         request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                //     };

                //     break;
                // case PAIR_PIN_SETUP_2:
                //     request = request.Concat(this.makeHead("POST", "/pair-setup-pin", null, true)).ToArray();
                //     u += "Content-Type: application/x-apple-binary-plist\r\n";
                //     using (var memoryStream = new MemoryStream())
                //     {
                //         BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                //         NSDictionary dict = new NSDictionary();
                //         dict.Add("pk", new NSData(this.A));
                //         dict.Add("proof", new NSData(this.M1));
                //         bplist.Write(dict);
                //         byte[] bpbuf = memoryStream.ToArray();

                //         u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                //         request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                //     };
                //     break;
                // case PAIR_PIN_SETUP_3:
                //     request = request.Concat(this.makeHead("POST", "/pair-setup-pin", null, true)).ToArray();
                //     u += "Content-Type: application/x-apple-binary-plist\r\n";
                //     using (var memoryStream = new MemoryStream())
                //     {
                //         BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                //         NSDictionary dict = new NSDictionary();
                //         dict.Add("epk", new NSData(this.epk));
                //         dict.Add("authTag", new NSData(this.authTag));
                //         bplist.Write(dict);
                //         byte[] bpbuf = memoryStream.ToArray();

                //         u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                //         request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                //     };
                //     break;
                // case PAIR_VERIFY_1:
                //     request = request.Concat(this.makeHead("POST", "/pair-verify", null, true)).ToArray();
                //     u += "Content-Type: application/octet-stream\r\n";
                //     this.pair_verify_1_verifier = LegacyATVVerifier.verifier(this.authSecret);
                //     u += "Content-Length:" + this.pair_verify_1_verifier["verifierBody"].Length + "\r\n\r\n";

                //     request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(Convert.FromHexString(this.pair_verify_1_verifier["verifierBody"])).ToArray();
                //     break;
                // case PAIR_VERIFY_2:
                //     request = request.Concat(this.makeHead("POST", "/pair-verify", null, true)).ToArray();
                //     u += "Content-Type: application/octet-stream\r\n";
                //     u += "Content-Length:" + this.pair_verify_1_signature.Length + "\r\n\r\n";

                //     request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(this.pair_verify_1_signature).ToArray();
                //     break;
                // case PAIR_SETUP_1:
                //     request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                //     u += "User-Agent: AirPlay/409.16\r\n";
                //     u += "CSeq: " + this.nextCSeq() + "\r\n";
                //     u += "Connection: keep-alive\r\n";
                //     u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                //     if (this.transient == true)
                //     {
                //         Dictionary<byte, byte[]> dic1 = new Dictionary<byte, byte[]>();
                //         dic1.Add(TlvTag.Sequence, new byte[] { 0x01 });
                //         dic1.Add(TlvTag.PairingMethod, new byte[] { 0x00 });
                //         dic1.Add(TlvTag.Flags, new byte[] { 0x00000010 });
                //         byte[] ps1x = Tlv.Encode(dic1);

                //         u += "Content-Length: " + ps1x.Length + "\r\n";
                //         u += "Content-Type: application/octet-stream" + "\r\n\r\n";
                //         request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps1x).ToArray();
                //     }
                //     else
                //     {
                //         Dictionary<byte, byte[]> dic2 = new Dictionary<byte, byte[]>();
                //         dic2.Add(TlvTag.PairingMethod, new byte[] { 0x00 });
                //         dic2.Add(TlvTag.Sequence, new byte[] { 0x01 });
                //         byte[] ps2x = Tlv.Encode(dic2);
                //         u += "Content-Length: " + ps2x.Length + "\r\n";
                //         u += "Content-Type: application/octet-stream" + "\r\n\r\n";
                //         request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps2x).ToArray();
                //     }
                //     break;
                // case PAIR_SETUP_2:
                //     request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                //     u += "User-Agent: AirPlay/409.16\r\n";
                //     u += "CSeq: " + this.nextCSeq() + "\r\n";
                //     u += "Connection: keep-alive\r\n";
                //     u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                //     u += "Content-Type: application/octet-stream\r\n";
                //     var dic = new Dictionary<byte, byte[]>();
                //     dic.Add(TlvTag.Sequence, new byte[] { 0x03 });
                //     dic.Add(TlvTag.PublicKey, Convert.FromHexString(this.A));
                //     dic.Add(TlvTag.Proof, Convert.FromHexString(this.M1));
                //     var ps2 = Tlv.Encode(dic);
                //     u += "Content-Length: " + ps2.Length + "\r\n\r\n";
                //     request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps2).ToArray();
                //     break;
                // case PAIR_SETUP_3:
                //     request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                //     u += "User-Agent: AirPlay/409.16\r\n";
                //     u += "CSeq: " + this.nextCSeq() + "\r\n";
                //     u += "Connection: keep-alive\r\n";
                //     u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                //     u += "Content-Type: application/octet-stream\r\n";
                //     this.K = Convert.FromHexString(this.srp.DeriveSession(this._hap_genkey, this._atv_pub_key, this._atv_salt, "Pair-Setup", this.srp.DerivePrivateKey(this._atv_salt, "Pair-Setup", this.password)).Key);
                //     this.seed = new byte[32];
                //     RandomNumberGenerator rng = RandomNumberGenerator.Create();
                //     rng.GetBytes(this.seed);
                //     var ed = new Ed25519();
                //     ed.FromSeed(this.seed);
                //     byte[] publicKey = ed.GetPublicKey();
                //     byte[] deviceHash = Encryption.HKDF(
                //         Encoding.ASCII.GetBytes("Pair-Setup-Controller-Sign-Salt"),
                //         this.K,
                //         Encoding.ASCII.GetBytes("Pair-Setup-Controller-Sign-Info"),
                //         32
                //     );
                //     byte[] deviceInfo = deviceHash.Concat(Encoding.ASCII.GetBytes(this.pairingId)).Concat(publicKey).ToArray();
                //     byte[] deviceSignature = ed.SignMessage(deviceInfo);
                //     // let deviceSignature = nacl.sign(deviceInfo, privateKey)
                //     this.encryptionKey = Encryption.HKDF(
                //         Encoding.ASCII.GetBytes("Pair-Setup-Encrypt-Salt"),
                //         this.K,
                //         Encoding.ASCII.GetBytes("Pair-Setup-Encrypt-Info"),
                //         32
                //     );
                //     Dictionary<byte, byte[]> dic3a = new Dictionary<byte, byte[]>();
                //     dic3a.Add(TlvTag.Username, Encoding.ASCII.GetBytes(this.pairingId));
                //     dic3a.Add(TlvTag.PublicKey, publicKey);
                //     dic3a.Add(TlvTag.Signature, deviceSignature);
                //     byte[] ps3xa = Tlv.Encode(dic3a);
                //     (byte[] encryptedTLV, byte[] encryptedTLVhmac) = Encryption.EncryptAndSeal(ps3xa, null, Encoding.ASCII.GetBytes("PS-Msg05"), this.encryptionKey);
                //     Dictionary<byte, byte[]> dic3b = new Dictionary<byte, byte[]>();
                //     dic3b.Add(TlvTag.Sequence, new byte[] { 0x05 });
                //     dic3b.Add(TlvTag.EncryptedData, encryptedTLV.Concat(encryptedTLVhmac).ToArray());
                //     byte[] ps3xb = Tlv.Encode(dic3b);
                //     u += "Content-Length: " + ps3xb.Length + "\r\n\r\n";
                //     request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps3xb).ToArray();
                //     break;
                // case PAIR_VERIFY_HAP_1:
                //     request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                //     u += "User-Agent: AirPlay/409.16\r\n";
                //     u += "CSeq: " + this.nextCSeq() + "\r\n";
                //     u += "Connection: keep-alive\r\n";
                //     u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                //     u += "Content-Type: application/octet-stream\r\n";
                //     var curve = new Curve25519();
                //     curve.FromPrivateKey(this.seed);
                //     this.verifyPrivate = curve.GetPrivateKey();
                //     this.verifyPublic = curve.GetPrivateKey();
                //     Dictionary<byte, byte[]> dic4 = new Dictionary<byte, byte[]>();
                //     dic4.Add(TlvTag.Sequence, new byte[] { 0x01 });
                //     dic4.Add(TlvTag.PublicKey, this.verifyPublic);
                //     byte[] ps4 = Tlv.Encode(dic4);
                //     u += "Content-Length: " + ps4.Length + "\r\n\r\n";
                //     request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps4).ToArray();
                //     break;
                // case PAIR_VERIFY_HAP_2:
                //     request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                //     u += "User-Agent: AirPlay/409.16\r\n";
                //     u += "CSeq: " + this.nextCSeq() + "\r\n";
                //     u += "Connection: keep-alive\r\n";
                //     u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                //     u += "Content-Type: application/octet-stream\r\n";
                //     //byte[] identifier = Tlv.Decode(this.verifier_hap_1["pairingData"])[TlvTag.Username];
                //     //byte[] signature = Tlv.Decode(this.verifier_hap_1["pairingData"])[TlvTag.Signature];
                //     byte[] material = this.verifyPublic.Concat(Encoding.ASCII.GetBytes(this.credentials.pairingId)).Concat(this.verifier_hap_1["sessionPublicKey"]).ToArray();
                //     var ed2 = new Ed25519();
                //     ed2.FromPrivateKey(this.privateKey);
                //     byte[] signed = ed2.SignMessage(material);
                //     Dictionary<byte, byte[]> dic5a = new Dictionary<byte, byte[]>();
                //     dic5a.Add(TlvTag.Username, Encoding.ASCII.GetBytes(this.pairingId));
                //     dic5a.Add(TlvTag.Signature, signed);
                //     byte[] ps5a = Tlv.Encode(dic5a);
                //     (byte[] encryptedTLV1, byte[] encryptedTLV1Hmac) = Encryption.EncryptAndSeal(ps5a, null, Encoding.ASCII.GetBytes("PV-Msg03"), this.verifier_hap_1["encryptionKey"]);
                //     Dictionary<byte, byte[]> dic5b = new Dictionary<byte, byte[]>();
                //     dic5b.Add(TlvTag.Sequence, new byte[] { 0x03 });
                //     dic5b.Add(TlvTag.EncryptedData, encryptedTLV1.Concat(encryptedTLV1Hmac).ToArray());
                //     byte[] ps5b = Tlv.Encode(dic5b);
                //     u += "Content-Length: " + ps5b.Length + "\r\n\r\n";
                //     request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps5b).ToArray();
                //     break;
                // case AUTH_SETUP:
                //     request = request.Concat(this.makeHead("POST", "/auth-setup", di)).ToArray();
                //     u += "Content-Length:" + "33" + "\r\n\r\n";
                //     byte[] auth_fakekey_buf = new byte[] {0x01, // unencrypted
                //             0x59, 0x02, 0xed, 0xe9, 0x0d, 0x4e, 0xf2, 0xbd, // static Curve 25519 key
                //             0x4c, 0xb6, 0x8a, 0x63, 0x30, 0x03, 0x82, 0x07,
                //             0xa9, 0x4d, 0xbd, 0x50, 0xd8, 0xaa, 0x46, 0x5b,
                //             0x5d, 0x8c, 0x01, 0x2a, 0x0c, 0x7e, 0x1d, 0x4e};
                //     request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(auth_fakekey_buf).ToArray();
                //     break;
                case HEARTBEAT:
                case OPTIONS:
                    request += MakeHead("OPTIONS", "*", digestInfo);
                    request += "Apple-Challenge: SdX9kFJVxgKVMFof/Znj4Q\r\n\r\n";
                    break;
                case OPTIONS2:
                    request += MakeHead("OPTIONS", "*", digestInfo, false);
                    request += "Apple-Challenge: SdX9kFJVxgKVMFof/Znj4Q\r\n\r\n";
                    break;
                case ANNOUNCE:
                    _announceId = NumUtil.RandomInt(8).ToString();
                    
                    if (_socket == null)
                        throw new InvalidOperationException("Socket is not connected");
                        
                    IPEndPoint localEndPoint = (IPEndPoint)_socket.Client.LocalEndPoint;
                    
                    body_str =
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
                        body_str +=
                            $"a=rsaaeskey:{Config.RsaAeskeyBase64}\r\n" +
                            $"a=aesiv:{Config.IvBase64}\r\n";
                    }

                    body = Encoding.UTF8.GetBytes(body_str);

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
                    body_str = $"volume: {attenuation :F6}\r\n";
                    body = Encoding.UTF8.GetBytes(body_str);
                    request += $"Content-Length: {body.Length}\r\n\r\n";
                    break;

                case TEARDOWN:
                    request += MakeHeadWithURL("TEARDOWN", digestInfo);
                    request += "\r\n";
                    break;

                case SETDAAP:
                    if (_trackInfo == null)
                        return;

                    string daapenc = "ascii";
                    //daapenc = true
                    byte[] name = DaapEncode("minm", daapenc, _trackInfo.Name);
                    byte[] artist = DaapEncode("asar", daapenc , _trackInfo.Artist);
                    byte[] album = DaapEncode("asal", daapenc, _trackInfo.Album);
                    byte[][] trackargs = new byte[][] { name, artist, album };

                    byte[] daapInfo = DaapEncodeList("mlit", daapenc, trackargs);
                        
                    request += MakeHeadWithURL("SET_PARAMETER", digestInfo);
                    request += "Content-Type: application/x-dmap-tagged\r\n";
                    
                    body = daapInfo;

                    
                    request += $"Content-Length: {daapInfo.Length}\r\n\r\n";
                    break;

                case SETART:
                    if (_artwork == null || _artworkContentType == null)
                        return;
                        
                    request += MakeHeadWithURL("SET_PARAMETER", digestInfo);
                    request += $"Content-Type: {_artworkContentType}\r\n";
                    body = _artwork;
                    request += $"Content-Length: {_artwork.Length}\r\n\r\n";
                    break;
            }

            if (request.Length > 0 && _socket != null)
            {
                try
                {
                    byte[] requestBytes = Encoding.UTF8.GetBytes(request).Concat(body).ToArray();
                    NetworkStream stream = _socket.GetStream();
                    stream.Write(requestBytes, 0, requestBytes.Length);
                    StartTimeout();
                }
                catch (Exception)
                {
                    Cleanup("socket_error");
                }
            }

            Console.WriteLine($"Sending request: {request} {Encoding.UTF8.GetString(body)}");
        }

        /// <summary>
        /// Calculates MD5 hash of a string
        /// </summary>
        /// <param name="input">Input string</param>
        /// <returns>MD5 hash as uppercase hex string or lowercase</returns>
        private string Md5(string input, bool uppercase = true)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    if (uppercase)
                        sb.Append(hashBytes[i].ToString("X2"));
                    else
                        sb.Append(hashBytes[i].ToString("x2"));
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
