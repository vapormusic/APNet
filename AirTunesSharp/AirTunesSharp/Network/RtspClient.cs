using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using AirTunesSharp.Utils;
using AirTunesSharp.Utils.HomeKit;
using SecureRemotePassword;
using Claunia.PropertyList;
using Rebex.Security.Cryptography;
using System.Diagnostics;
using AirTunesSharp.Audio;
using Makaretu.Dns;

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
        SETPROGRESS = 28,
        INFO = -1;

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
        private long? progress;
        private long? duration;
        private Action<object[]>? _callback;
        private int? _controlPort;
        private int? _timingPort;
        private int? _serverPort;
        private int? _timingDestPort;
        private int? _eventPort;
        private System.Timers.Timer? _heartBeat;

        private Dictionary<string, string>? _digestInfo;

        private bool _triedMd5Uppercase = false;

        private long starttime;

        private string I = "366B4165DD64AD3A";
        private string P;
        private string s;
        private string B;
        private string A;
        private string a;
        private byte[] Al;
        private string M1;
        private SrpSession M1Session;
        private string epk;
        private string authTag;
        private string _atv_salt;
        private string _atv_pub_key;
        private string _hap_genkey;
        private byte[] _hap_encrypteddata;
        private string? pairingId;
        private byte[] K;
        private byte[] seed;
        private byte[] sharedSecret;
        private Credentials credentials;
        private byte[] event_credentials;
        private Dictionary<string, byte[]>? verifier_hap_1;
        private byte[] verifyPrivate;
        private byte[] verifyPublic;
        private byte[] encryptionKey;
        private bool encryptedChannel;
        private string hostip;
        private string homekitver;

        private Dictionary<string, string>? pair_verify_1_verifier;
        private byte[] pair_verify_1_signature;
        private string code_digest;
        private string authSecret;
        private int mode;
        private string[] dnstxt;
        private bool alacEncoding;
        private bool needPassword;
        private bool airplay2;
        private bool needPin;
        private bool debug;
        private bool transient;
        // private bool borkedshp;
        private byte[] privateKey;
        private byte[] deviceProof;
        private SrpClient? srp;
        private TcpClient? eventsocket;

        /// <summary>
        /// Initializes a new instance of the RtspClient class
        /// </summary>
        /// <param name="volume">Initial volume</param>
        /// <param name="password">Password for authentication</param>
        /// <param name="audioOut">Audio output manager</param>
        public RtspClient(int volume, string? password, Audio.AudioOut audioOut, dynamic? options = null)
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
            pair_verify_1_verifier = null;
            pair_verify_1_signature = null;
            code_digest = null;
            authSecret = null;
            mode = options?.mode ?? 0;
            dnstxt = options?.txt ?? new string[0];
            alacEncoding = options?.alacEncoding ?? true;
            needPassword = options?.needPassword ?? false;
            airplay2 = options?.airplay2 ?? false;
            needPin = options?.needPin ?? false;
            debug = options?.debug ?? false;
            transient = options?.transient ?? false;
            // borkedshp = options?.borkedshp ?? false;
            privateKey = null;
            srp = null;
            I = "366B4165DD64AD3A";
            P = null;
            s = null;
            B = null;
            a = null;
            A = null;
            M1 = null;
            epk = null;
            authTag = null;
            _atv_salt = null;
            _atv_pub_key = null;
            _hap_genkey = null;
            _hap_encrypteddata = null;
            pairingId = null;
            seed = null;
            credentials = null;
            event_credentials = null;
            verifier_hap_1 = null;
            encryptionKey = null;
            encryptedChannel = false;
            hostip = null;
            homekitver = (transient == true) ? "4" : "3";
            starttime = 0;
            progress = 0;
            duration = 0;

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
            hostip = host;

            _socket = new TcpClient();
            _socket.ReceiveTimeout = 40000;
            _socket.SendTimeout = 40000;           
            try
            {
                _socket.ConnectAsync(host, port).ContinueWith(t => 
                {
                    if (t.IsFaulted)
                    {
                        Cleanup("connection_refused");
                        return;
                    }

                    if (needPassword || needPin)
                    {
                        _status = PAIR_PIN_START;
                        SendNextRequest();
                        StartHeartBeat();
                        ClearTimeout();
                    }
                    else
                    {
                        if (this.mode != 2)
                        {
                            Debug.WriteLine("s2");
                            if (this.debug) Debug.WriteLine("AUTH_SETUP", "nah");
                            _status = OPTIONS;
                            ClearTimeout();
                            SendNextRequest();
                            StartHeartBeat();
                        }
                        else
                        {
                            Debug.WriteLine("s3");
                            _status = AUTH_SETUP;
                            if (this.debug) Debug.WriteLine("AUTH_SETUP", "yah");
                            ClearTimeout();
                            SendNextRequest();
                            StartHeartBeat();
                        }

                        ClearTimeout();


                    }



                    NetworkStream stream = _socket.GetStream();
                    byte[] buffer = new byte[100000];
                    StringBuilder blob = new StringBuilder();
                    bool encryptedOkay = false;
                    var encryptedBlob = new byte[0];
                    var decrpytedData = new byte[0];
                    
                    int lastRead = 0;

                    Task.Run(async () => 
                    {
                        try
                        {
                            while (_socket != null && _socket.Connected)
                            {
                                using (MemoryStream ms = new MemoryStream())
                                {
                                    byte[] buffer = new byte[81920];
                                    do
                                    {
                                        lastRead = stream.Read(buffer, 0, buffer.Length);
                                        ms.Write(buffer, 0, lastRead);
                                    } while (lastRead > buffer.Length);
                                    encryptedBlob = ms.ToArray();
                                    int[] x = (new int[] { PAIR_SETUP_1, PAIR_SETUP_2, PAIR_SETUP_3, PAIR_VERIFY_HAP_1, PAIR_VERIFY_HAP_2 });
                                    // if (Encoding.UTF8.GetString(encryptedBlob) == "")
                                    // {
                                    //     Cleanup("done");
                                    // }
                                    if (this.encryptedChannel && this.credentials != null)
                                    {
                                        decrpytedData = this.credentials.decrypt(encryptedBlob);
                                    } else {
                                        decrpytedData = encryptedBlob;
                                    }
                                    lastRead = 0;
                                    buffer = new byte[81920];
                                    ClearTimeout();

                                    string data = Encoding.UTF8.GetString(decrpytedData, 0, decrpytedData.Length);
                                    blob.Append(data);

                                    int endIndex = blob.ToString().IndexOf("\r\n\r\n");
                                    if (endIndex < 0)
                                         continue;

                                    endIndex += 4;
                                    string response = blob.ToString().Substring(0, endIndex);           


                                    Debug.WriteLine("Received:");
                                    Debug.WriteLine(Encoding.UTF8.GetString(decrpytedData));
                                    ProcessData(response,decrpytedData);
                                    blob.Clear();

                                    if (endIndex < data.Length)
                                        blob.Append(data.Substring(endIndex));
                                    decrpytedData = new byte[0];
                            }

                                // int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                                // if (bytesRead <= 0)
                                // {
                                //     Cleanup("disconnected");
                                //     break;
                                // }

                                // do             
                                // {
                                //     lastRead = stream.Read(buffer, 0, buffer.Length);
                                //     ms.Write(buffer, 0, lastRead);
                                // } while (lastRead > buffer.Length);

                                // ClearTimeout();
                                // encryptedBlob = encryptedBlob.Concat(buffer.Take(bytesRead).ToArray()).ToArray();

                                // if (encryptedChannel && credentials != null)
                                // {          

                                //     byte[] lengthbytes = encryptedBlob.Take(2).ToArray();
                                //     int length = BitConverter.ToUInt16(lengthbytes, 0);
                                //     if (encryptedBlob.Length == length - 16 - 2)
                                //     {
                                //         buffer = credentials.decrypt(encryptedBlob);
                                //         encryptedOkay = true;
                                //         encryptedBlob = new byte[0];
                                //     }

                                // }
                                // else {
                                //     encryptedOkay = true;
                                // }
                                // if (encryptedOkay){

                                //     string data = Encoding.UTF8.GetString(buffer, 0, Math.Min(bytesRead, buffer.Length));
                                //     blob.Append(data);

                                //     int endIndex = blob.ToString().IndexOf("\r\n\r\n");
                                //     if (endIndex < 0 && encryptedOkay)
                                //         continue;

                                //     endIndex += 4;
                                //     string response = blob.ToString().Substring(0, endIndex);                


                                //     ProcessData(response, buffer);

                                //     blob.Clear();
                                //     if (endIndex < data.Length)
                                //         blob.Append(data.Substring(endIndex));
                                // }
                            }
                        }
                        catch (Exception ex)
                        {
                            if (_socket != null)
                            {
                                _socket = null;
                                Console.WriteLine(ex.StackTrace);
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
            if (_timeout != null)
            {
                _timeout.Stop();
                _timeout.Dispose();
            } 
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
            if (name != _trackInfo?.Name || artist != _trackInfo?.Artist || album != _trackInfo?.Album)
            {
                this.starttime = _audioOut.LastSeq * 352 + 2 * 44100;
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
        /// Sets duration and progress for the current track
        /// </summary>
        /// <param name="progress">Progress in seconds</param>
        /// <param name="duration">Duration in seconds</param>
        /// <param name="callback">Callback function</param>
        public void SetProgress(long progress, long duration, Action<object[]> callback)
        {
            if ((_status < 2) || ((_status > 10) && (_status < 26))  )
            {
               return;         
            }
            this.progress = progress;
            this.duration = duration;
            _callback = callback;
            _status = SETPROGRESS;
            SendNextRequest();
        } 



        /// <summary>
        /// Sets the passcode for pairing
        /// </summary>
        /// <param name="passcode">Passcode</param>
        public void SetPasscode(string passcode) {
            _password = passcode;
            _status = this.airplay2 ? PAIR_SETUP_1 : (this.needPin ? PAIR_PIN_SETUP_1 : OPTIONS);
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
        private void ProcessData(string blob, byte[] rawData)
        {
            RtspResponse response = RtspResponse.ParseResponse(blob);
            Console.WriteLine($"Resp status: {_status} {response.Code} {response.Status}");
            Console.WriteLine($"Headers: {string.Join(Environment.NewLine, response.Headers)}");
            Console.WriteLine($"Body: {response.Body}");


            string responseText = Encoding.UTF8.GetString(rawData);
            // Get the headers
            string[] headers_p = responseText.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.None);
            string[] headerLines = headers_p[0].Split(new string[] { "\r\n" }, StringSplitOptions.None);
            string[] statusLine = headerLines[0].Split(" ");
    
            byte[] body = new byte[0];
            if (headers_p.Length > 1)
            {
                body = rawData.Skip(headers_p[0].Length + 4).ToArray();
            }
            

            if (response.Code >= 400 & response.Code != 416)
            {
                if (response.Code == 401 && !_passwordTried && (_password != null && _password.Length > 0))
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
                if (response.Code == 401 && !(_password != null && _password.Length > 0) && !transient && _status == OPTIONS)
                {
                    Emit("need_password");
                    _passwordTried = false;
                    return;
                }
                // if (_status != OPTIONS)
                // {
                //     Cleanup("rtsp_error", response.Status);
                //     return;
                // }
                if(response.Code == 403 && _status == ANNOUNCE && this.mode == 2) {
                        _status = AUTH_SETUP;
                        SendNextRequest();
                        return;
                }

                if (response.Code == 453)
                {
                    Debug.WriteLine("busy");
                    Cleanup("busy", "Device is busy");
                    return;
                }

                if (response.Code != 200)
                {
                    if (_status != SETVOLUME && _status != SETPEERS && _status != FLUSH && _status != RECORD && _status != GETVOLUME && _status != SETPROGRESS && _status != SETDAAP && _status != SETART)
                    {
                        if ((new int[] {PAIR_VERIFY_1,
                              PAIR_VERIFY_2,
                              AUTH_SETUP,
                              PAIR_PIN_START,
                              PAIR_PIN_SETUP_1,
                              PAIR_PIN_SETUP_2,
                              PAIR_PIN_SETUP_3}).Contains(_status))
                        {
                            Emit("pair_failed", "");
                        }
                        Cleanup("rtsp_error", response.Status);
                        return;
                    }
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
                case PAIR_PIN_START:
                    if (!this.transient && _password == null) { 
                        Emit("need_password");
                    }
                    _status = airplay2 ? PAIR_SETUP_1 : PAIR_PIN_SETUP_1;
                    break;
                case PAIR_PIN_SETUP_1:
                    var N = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
                            "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
                            "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
                            "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
                            "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
                            "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
                            "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
                            "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
                            "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
                            "9E4AFF73";
                    var customParams = SrpParameters.Create<SHA1>(N, "02");
                    srp = new SrpClient();
                    P = _password;
                    var pps1_bplist = BinaryPropertyListParser.Parse(body) as NSDictionary;
                    Debug.WriteLine(BinaryPropertyListParser.Parse(body).ToXmlPropertyList());
                    s = Convert.ToHexString((pps1_bplist.Get("salt") as NSData).Bytes);
                    B = Convert.ToHexString((pps1_bplist.Get("pk") as NSData).Bytes);
                    NSDictionary dict = new NSDictionary();
                    // SRP: Generate random auth_secret, "a"; if pairing is successful, it"ll be utilized in
                    // subsequent session authentication(s).

                    // SRP: Compute A and M1.
                    var srpEphemeral = this.srp.GenerateEphemeral();
                    this.a = srpEphemeral.Secret;
                    this.A = srpEphemeral.Public;
                    this.M1 = this.srp.DeriveSession(this.a, this.B, this.s, this.I, this.srp.DerivePrivateKey(this.s, this.I, this.P)).Proof;
                    _status = PAIR_PIN_SETUP_2;
                    break;
                case PAIR_PIN_SETUP_2:
                    Dictionary<string, string> pps2_dict = LegacyATVVerifier.confirm(this.a, this.M1);
                    this.epk = pps2_dict["epk"];
                    this.authTag = pps2_dict["authTag"];
                    _status = PAIR_PIN_SETUP_3;
                    break;
                case PAIR_PIN_SETUP_3:
                    _status = PAIR_VERIFY_1;
                    this.authSecret = this.a;
                    break;
                case PAIR_VERIFY_1:
                    string atv_pub = Convert.ToHexString(body.Skip(0).Take(32).ToArray());
                    string atv_data = Convert.ToHexString(body.Skip(32).ToArray());

                    string shared = LegacyATVVerifier.shared(v_pri: this.pair_verify_1_verifier["v_pri"], atv_pub);
                    string signed = LegacyATVVerifier.signed(this.authSecret, this.pair_verify_1_verifier["v_pub"], atv_pub);
                    this.pair_verify_1_signature = (new byte[] { 0x00, 0x00, 0x00, 0x00 }).Concat(Convert.FromHexString(LegacyATVVerifier.signature(shared, atv_data, signed))).ToArray();
                    _status = PAIR_VERIFY_2;
                    break;
                case PAIR_VERIFY_2:
                    _status = this.mode == 2 ? AUTH_SETUP : OPTIONS;
                    break;
                case PAIR_SETUP_1:
                    Debug.WriteLine("yah");
                    Dictionary<byte, byte[]> databuf1 = Tlv.Decode(body);
                    Debug.WriteLine(databuf1.ToString());
                    if (databuf1.ContainsKey(TlvTag.BackOff)) {
                        byte[] backOff = databuf1[TlvTag.BackOff];
                        int seconds = BitConverter.ToInt16(backOff, 0);

                        Debug.WriteLine("You've attempt to pair too recently. Try again in " + (seconds.ToString()) + " seconds.");

                    }
                    if (databuf1.ContainsKey(TlvTag.ErrorCode))
                    {
                        byte[] buffer = databuf1[TlvTag.ErrorCode];
                        Debug.WriteLine("Device responded with error code " + Convert.ToSByte(buffer).ToString() + ". Try rebooting your Apple TV.");
                    }
                    if (databuf1.ContainsKey(TlvTag.PublicKey))
                    {
                        this._atv_pub_key = Convert.ToHexString(databuf1[TlvTag.PublicKey]);
                        this._atv_salt = Convert.ToHexString(databuf1[TlvTag.Salt]);
                        //this._hap_genkey = new byte[32];
                        //RandomNumberGenerator rng = RandomNumberGenerator.Create();
                        //rng.GetBytes(this._hap_genkey);
                        if (_password == null)
                        {
                            _password = "3939"; // transient
                        }
                        string SRP_AP2_N = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
                                "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
                                "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
                                "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
                                "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
                                "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
                                "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
                                "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
                                "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
                                "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
                                "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
                                "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
                                "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
                        var customParams_ap2 = SrpParameters.Create<SHA512>(SRP_AP2_N, "05");
                        this.srp = new SrpClient(customParams_ap2);
                        //this.srp = new SrpClient(SRP.params.hap,
                        //Buffer.from(this._atv_salt), //salt
                        //Buffer.from("Pair-Setup"), //identity
                        //Buffer.from(this.password.toString()), //password
                        //Buffer.from(this._hap_genkey), true) // sec
                        var srpEphemeral2 = this.srp.GenerateEphemeral();
                        this._hap_genkey = srpEphemeral2.Secret;
                        this.A = srpEphemeral2.Public;
                        this.M1Session = this.srp.DeriveSession(this._hap_genkey, this._atv_pub_key, this._atv_salt, "Pair-Setup", this.srp.DerivePrivateKey(this._atv_salt, "Pair-Setup", _password));
                        this.M1 = M1Session.Proof;
                        _status = PAIR_SETUP_2;
                    } else {
                        Emit("end", "no pk");
                        Cleanup("pair_failed");
                        return;
                    }
                    break;
                case PAIR_SETUP_2:
                    Dictionary<byte, byte[]> databuf2 = Tlv.Decode(body);
                    this.deviceProof = databuf2[TlvTag.Proof];
                    // console.log("DEBUG: Device Proof=" + this.deviceProof.toString("hex"));
                    srp.VerifySession(this.A, this.M1Session, Convert.ToHexString(this.deviceProof));
                    if (this.transient == true)
                    {
                        this.credentials = new Credentials(
                          "sdsds",
                          new byte[0],
                          "",
                          new byte[0],
                          this.seed
                        );
                        this.credentials.writeKey = Encryption.HKDF(
                          Encoding.ASCII.GetBytes("Control-Salt"),
                          Convert.FromHexString(this.M1Session.Key),
                          Encoding.ASCII.GetBytes("Control-Write-Encryption-Key"),
                          32
                        );
                        Debug.WriteLine("hmm " + this.credentials.writeKey.Length);
                        this.credentials.readKey = Encryption.HKDF(
                          Encoding.ASCII.GetBytes("Control-Salt"),
                          Convert.FromHexString(this.M1Session.Key),
                          Encoding.ASCII.GetBytes("Control-Read-Encryption-Key"),
                          32
                        );
                        Console.WriteLine("write " + Convert.ToHexString(this.credentials.writeKey));
                        this.encryptedChannel = true;
                        _status = SETUP_AP2_1;
                    }
                    else
                    {
                        _status = PAIR_SETUP_3;
                    }
                    break;
                case PAIR_SETUP_3:
                    byte[] encryptedData = Tlv.Decode(body)[TlvTag.EncryptedData];
                    byte[] cipherText = encryptedData.Skip(0).Take(encryptedData.Length - 16).ToArray();
                    byte[] hmac = encryptedData.Skip(encryptedData.Length - 16).Take(16).ToArray();
                    byte[] decrpytedData = Encryption.VerifyAndDecrypt(cipherText, hmac, null, Encoding.ASCII.GetBytes("PS-Msg06"), this.encryptionKey);
                    Dictionary<byte, byte[]> tlvData = Tlv.Decode(decrpytedData);
                    this.credentials = new Credentials(
                       "sdsds",
                       tlvData[TlvTag.Username],
                       pairingId,
                       tlvData[TlvTag.PublicKey],
                      this.seed
                     );
                    _status = PAIR_VERIFY_HAP_1;
                    break;
                case PAIR_VERIFY_HAP_1:
                    Dictionary<byte, byte[]> decodedData = Tlv.Decode(body);
                    byte[] sessionPublicKey = decodedData[TlvTag.PublicKey];
                    byte[] encryptedData1 = decodedData[TlvTag.EncryptedData];

                    if (sessionPublicKey.Length != 32)
                    {
                        throw new Exception(String.Format("sessionPublicKey must be 32 bytes(but was {0})", sessionPublicKey.Length));
                    }
                    byte[] cipherText1 = encryptedData1.Skip(0).Take(encryptedData1.Length - 16).ToArray();
                    byte[] hmac1 = encryptedData1.Skip(encryptedData1.Length - 16).Take(16).ToArray();
                    // let sharedSecret = curve25519.deriveSharedSecret(this.verifyPrivate, sessionPublicKey);
                    var curve25519 = new Curve25519();
                    curve25519.FromPrivateKey(this.verifyPrivate);
                    byte[] sharedSecret = curve25519.GetSharedSecret(sessionPublicKey);
                    byte[] encryptionKey = Encryption.HKDF(
                        Encoding.ASCII.GetBytes("Pair-Verify-Encrypt-Salt"),
                        sharedSecret,
                        Encoding.ASCII.GetBytes("Pair-Verify-Encrypt-Info"),
                        32
                    );
                    byte[] decryptedData = Encryption.VerifyAndDecrypt(cipherText1, hmac1, null, Encoding.ASCII.GetBytes("PV-Msg02"), encryptionKey);
                    this.verifier_hap_1 = new Dictionary<string, byte[]>();
                    this.verifier_hap_1.Add("sessionPublicKey", sessionPublicKey);
                    this.verifier_hap_1.Add("sharedSecret", sharedSecret);
                    this.verifier_hap_1.Add("encryptionKey", encryptionKey);
                    this.verifier_hap_1.Add("pairingData", decryptedData);
                    _status = PAIR_VERIFY_HAP_2;
                    this.sharedSecret = sharedSecret;
                    break;
                case PAIR_VERIFY_HAP_2:
                    this.credentials.readKey = Encryption.HKDF(
                      Encoding.ASCII.GetBytes("Control-Salt"),
                      this.sharedSecret,
                      Encoding.ASCII.GetBytes("Control-Read-Encryption-Key"),
                      32
                    );
                    this.credentials.writeKey = Encryption.HKDF(
                      Encoding.ASCII.GetBytes("Control-Salt"),
                      this.sharedSecret,
                      Encoding.ASCII.GetBytes("Control-Write-Encryption-Key"),
                      32
                    );
                    //if (this.debug) { console.log("write", this.credentials.writeKey)}
                    //if (this.debug) { console.log("buf6", buf6)}
                    this.encryptedChannel = true;
                    _status = (this.mode == 2 ? AUTH_SETUP : SETUP_AP2_1);
                    break;
                case SETUP_AP2_1:
                    Debug.WriteLine("timing port parsing");
                    NSDictionary sa1_bplist = BinaryPropertyListParser.Parse(body) as NSDictionary;
                    Debug.WriteLine(sa1_bplist.ToXmlPropertyList());
                    _eventPort = ((NSNumber)sa1_bplist.ObjectForKey("eventPort")).ToInt();
                    if (sa1_bplist.TryGetValue("timingPort", out NSObject timingPort)) {
                        this._timingDestPort = ((NSNumber)sa1_bplist.ObjectForKey("timingPort")).ToInt();
                    }
                    Debug.WriteLine("timing port parsing ", _eventPort.ToString());
                    _status = SETPEERS;
                    
                    break;
                case SETUP_AP2_2:
                    NSDictionary sa2_bplist = BinaryPropertyListParser.Parse(body) as NSDictionary;
                    Debug.WriteLine(sa2_bplist.ToXmlPropertyList());
                    NSDictionary stream = ((NSArray)sa2_bplist.ObjectForKey("streams")).First() as NSDictionary;
                    Emit("config", new
                    {
                        audioLatency = 50,
                        requireEncryption = _requireEncryption,
                        server_port = ((NSNumber)stream.ObjectForKey("dataPort")).ToInt(),
                        control_port = ((NSNumber)stream.ObjectForKey("controlPort")).ToInt(),
                        timing_port = (this._timingDestPort != null) ? this._timingDestPort : _timingPort,
                        credentials = this.credentials
                    });
                    _status = RECORD;
                    break;
                case SETPEERS:
                    _status = SETUP_AP2_2;
                    break;
                case FLUSH:
                    _status = PLAYING;
                    Emit("pair_success");
                    _session = "1";
                    Emit("ready");
                    break;
                case INFO:
                    _status = (this.credentials != null) ? RECORD : PAIR_SETUP_1;
                    break;
                case GETVOLUME:
                    _status = RECORD;
                    break;
                case AUTH_SETUP:
                    _status = this.airplay2 ? SETUP_AP2_1 : OPTIONS;
                    break;
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
                        _status = (_session != null) ? PLAYING : (this.airplay2 ? PAIR_PIN_START : ANNOUNCE);
                        if (_status == ANNOUNCE) { Emit("pair_success"); };
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
                        timing_port = _timingPort,
                        credentials = credentials,
                    });
                    _status = RECORD;
                    break;
                    
                case RECORD:
                    if (_status != SETDAAP && _status != SETART && _status != SETVOLUME && _status != SETPROGRESS)
                        _status = PLAYING;
                    Emit("ready");
                    break;
                case SETPROGRESS:
                    if (_status != SETDAAP && _status != SETART && _status != SETVOLUME)
                        _status = PLAYING;
                    break;    
                case SETVOLUME:
                    if (_status != SETDAAP && _status != SETART && _status != SETPROGRESS)
                        _status = PLAYING;
                    break;
                case SETDAAP:
                    if (_status != SETVOLUME && _status != SETART && _status != SETPROGRESS)
                        _status = PLAYING;
                    break;
                case SETART:
                    if (_status != SETVOLUME && _status != SETDAAP && _status != SETPROGRESS)
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
        private string MakeHead(string method, string uri, Dictionary<string, string>? digestInfo = null, bool md5Uppercase = true, bool clear = false)
        {
            string head = $"{method} {uri} RTSP/1.0\r\n";
            if (!clear) {
              head +=  $"CSeq: {NextCSeq()}\r\n" +
                $"User-Agent: {Config.UserAgent}\r\n" +
                $"DACP-ID: {_dacpId.ToUpper()}\r\n" +
                $"Client-Instance: {_dacpId.ToUpper()}\r\n" +
                (_session != null ? $"Session: {_session}\r\n" : "") +
                $"Active-Remote: {_activeRemote}\r\n";
            }
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
                case PAIR_PIN_START:
                    I = "366B4165DD64AD3A";
                    P = null;
                    s = null;
                    B = null;
                    a = null;
                    A = null;
                    M1 = null;
                    epk = null;
                    authTag = null;
                    _atv_salt = null;
                    _atv_pub_key = null;
                    _hap_encrypteddata = null;
                    seed = null;
                    pairingId = Guid.NewGuid().ToString();
                    credentials = null;
                    verifier_hap_1 = null;
                    encryptionKey = null;
                    if (needPin ||airplay2)
                    {
                        request = MakeHead("POST", "/pair-pin-start", null, clear: true);
                        if (airplay2)
                        {

                            request += "User-Agent: AirPlay/490.16\r\n";
                            request += "Connection: keep-alive\r\n";
                            request += "CSeq: " + "0" + "\r\n";

                        }
                        request += "Content-Length:" + 0 + "\r\n\r\n";
                        
                    } else
                    {
                        if (_password == null)
                        {
                            Emit("need_password");
                        }
                        _status = airplay2 ? INFO : (needPin ? PAIR_PIN_SETUP_1: OPTIONS);
                        SendNextRequest();
                        return;
                    }
                    break;
                case PAIR_PIN_SETUP_1:
                    request = MakeHead("POST", "/pair-setup-pin", null, clear: true);
                    request += "Content-Type: application/x-apple-binary-plist\r\n";

                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary dict = new NSDictionary();
                        dict.Add("user", "366B4165DD64AD3A");
                        dict.Add("method", "pin");
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();
                        body = bpbuf;

                        request += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                    };

                    break;
                case PAIR_PIN_SETUP_2:
                    request = MakeHead("POST", "/pair-setup-pin", null, clear: true);
                    request += "Content-Type: application/x-apple-binary-plist\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary dict = new NSDictionary();
                        dict.Add("pk", new NSData(A));
                        dict.Add("proof", new NSData(M1));
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();
                        body = bpbuf;

                        request += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                    };
                    break;
                case PAIR_PIN_SETUP_3:
                    request = MakeHead("POST", "/pair-setup-pin", null, clear: true);
                    request += "Content-Type: application/x-apple-binary-plist\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary dict = new NSDictionary();
                        dict.Add("epk", new NSData(epk));
                        dict.Add("authTag", new NSData(authTag));
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();
                        body = bpbuf;

                        request += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                    };
                    break;
                case PAIR_VERIFY_1:
                    request = MakeHead("POST", "/pair-verify", null, clear: true);
                    request += "Content-Type: application/octet-stream\r\n";
                    pair_verify_1_verifier = LegacyATVVerifier.verifier(authSecret);
                    request += "Content-Length:" + pair_verify_1_verifier["verifierBody"].Length + "\r\n\r\n";
                    body = Convert.FromHexString(pair_verify_1_verifier["verifierBody"]);
        
                    break;
                case PAIR_VERIFY_2:
                    request = MakeHead("POST", "/pair-verify", null, clear: true);
                    request += "Content-Type: application/octet-stream\r\n";
                    request += "Content-Length:" + pair_verify_1_signature.Length + "\r\n\r\n";
                    body = pair_verify_1_signature;

                    break;
                case PAIR_SETUP_1:
                    request = MakeHead("POST", "/pair-setup", null, clear: true);
                    request += "User-Agent: AirPlay/490.16\r\n";
                    request += "CSeq: " + NextCSeq() + "\r\n";
                    request += "Connection: keep-alive\r\n";
                    request += "X-Apple-HKP: " + homekitver + "\r\n";
                    if (transient == true)
                    {
                        Dictionary<byte, byte[]> dic1 = new Dictionary<byte, byte[]>();
                        dic1.Add(TlvTag.Sequence, new byte[] { 0x01 });
                        dic1.Add(TlvTag.PairingMethod, new byte[] { 0x00 });
                        dic1.Add(TlvTag.Flags, new byte[] { 0x00000010 });
                        byte[] ps1x = Tlv.Encode(dic1);
                        body = ps1x;

                        request += "Content-Length: " + ps1x.Length + "\r\n";
                        request += "Content-Type: application/octet-stream" + "\r\n\r\n";
                    }
                    else
                    {
                        Dictionary<byte, byte[]> dic2 = new Dictionary<byte, byte[]>();
                        dic2.Add(TlvTag.PairingMethod, new byte[] { 0x00 });
                        dic2.Add(TlvTag.Sequence, new byte[] { 0x01 });
                        byte[] ps2x = Tlv.Encode(dic2);
                        body = ps2x;
                        request += "Content-Length: " + ps2x.Length + "\r\n";
                        request += "Content-Type: application/octet-stream" + "\r\n\r\n";
                    }
                    break;
                case PAIR_SETUP_2:
                    request = MakeHead("POST", "/pair-setup", null, clear: true);
                    request += "User-Agent: AirPlay/490.16\r\n";
                    request += "CSeq: " + NextCSeq() + "\r\n";
                    request += "Connection: keep-alive\r\n";
                    request += "X-Apple-HKP: " + homekitver + "\r\n";
                    request += "Content-Type: application/octet-stream\r\n";

                    var dic = new Dictionary<byte, byte[]>();
                    dic.Add(TlvTag.Sequence, new byte[] { 0x03 });
                    dic.Add(TlvTag.PublicKey, Convert.FromHexString(this.A));
                    dic.Add(TlvTag.Proof, Convert.FromHexString(this.M1));
                    var ps2 = Tlv.Encode(dic);
                    body = ps2;

                    request += "Content-Length: " + ps2.Length + "\r\n\r\n";

                    break;
                case PAIR_SETUP_3:
                    request = MakeHead("POST", "/pair-setup", null, clear: true);
                    request += "User-Agent: AirPlay/490.16\r\n";
                    request += "CSeq: " + NextCSeq() + "\r\n";
                    request += "Connection: keep-alive\r\n";
                    request += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    request += "Content-Type: application/octet-stream\r\n";
                    K = Convert.FromHexString(srp.DeriveSession(_hap_genkey, 
                                                                _atv_pub_key, 
                                                                _atv_salt, 
                                                                "Pair-Setup", 
                                                                srp.DerivePrivateKey(_atv_salt, 
                                                                                          "Pair-Setup", 
                                                                                          _password)).Key);
                    seed = new byte[32];
                    RandomNumberGenerator rng = RandomNumberGenerator.Create();
                    rng.GetBytes(this.seed);
                    var ed = new Ed25519();
                    ed.FromSeed(this.seed);
                    byte[] publicKey = ed.GetPublicKey();
                    byte[] deviceHash = Encryption.HKDF(
                        Encoding.ASCII.GetBytes("Pair-Setup-Controller-Sign-Salt"),
                        this.K,
                        Encoding.ASCII.GetBytes("Pair-Setup-Controller-Sign-Info"),
                        32
                    );
                    byte[] deviceInfo = deviceHash.Concat(Encoding.ASCII.GetBytes(pairingId)).Concat(publicKey).ToArray();
                    byte[] deviceSignature = ed.SignMessage(deviceInfo);
                    // let deviceSignature = nacl.sign(deviceInfo, privateKey)
                    this.encryptionKey = Encryption.HKDF(
                        Encoding.ASCII.GetBytes("Pair-Setup-Encrypt-Salt"),
                        this.K,
                        Encoding.ASCII.GetBytes("Pair-Setup-Encrypt-Info"),
                        32
                    );
                    Dictionary<byte, byte[]> dic3a = new Dictionary<byte, byte[]>();
                    dic3a.Add(TlvTag.Username, Encoding.ASCII.GetBytes(pairingId));
                    dic3a.Add(TlvTag.PublicKey, publicKey);
                    dic3a.Add(TlvTag.Signature, deviceSignature);
                    byte[] ps3xa = Tlv.Encode(dic3a);
                    (byte[] encryptedTLV, byte[] encryptedTLVhmac) = Encryption.EncryptAndSeal(ps3xa, null, Encoding.ASCII.GetBytes("PS-Msg05"), this.encryptionKey);
                    Dictionary<byte, byte[]> dic3b = new Dictionary<byte, byte[]>();
                    dic3b.Add(TlvTag.Sequence, new byte[] { 0x05 });
                    dic3b.Add(TlvTag.EncryptedData, encryptedTLV.Concat(encryptedTLVhmac).ToArray());
                    byte[] ps3xb = Tlv.Encode(dic3b);
                    body = ps3xb;

                    request += "Content-Length: " + ps3xb.Length + "\r\n\r\n";
                    break;
                case PAIR_VERIFY_HAP_1:
                    request = MakeHead("POST", "/pair-verify", null, clear: true);
                    request += "User-Agent: AirPlay/490.16\r\n";
                    request += "CSeq: " + NextCSeq() + "\r\n";
                    request += "Connection: keep-alive\r\n";
                    request += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    request += "Content-Type: application/octet-stream\r\n";
                    var curve = new Curve25519();
                    curve.FromPrivateKey(this.seed);
                    verifyPrivate = curve.GetPrivateKey();
                    verifyPublic = curve.GetPrivateKey();
                    Dictionary<byte, byte[]> dic4 = new Dictionary<byte, byte[]>();
                    dic4.Add(TlvTag.Sequence, new byte[] { 0x01 });
                    dic4.Add(TlvTag.PublicKey, this.verifyPublic);
                    byte[] ps4 = Tlv.Encode(dic4);
                    body = ps4;
                    request += "Content-Length: " + ps4.Length + "\r\n\r\n";

                    break;
                case PAIR_VERIFY_HAP_2:
                    request = MakeHead("POST", "/pair-verify", null, clear: true);
                    request += "User-Agent: AirPlay/490.16\r\n";
                    request += "CSeq: " + NextCSeq() + "\r\n";
                    request += "Connection: keep-alive\r\n";
                    request += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    request += "Content-Type: application/octet-stream\r\n";
                    //byte[] identifier = Tlv.Decode(this.verifier_hap_1["pairingData"])[TlvTag.Username];
                    //byte[] signature = Tlv.Decode(this.verifier_hap_1["pairingData"])[TlvTag.Signature];
                    byte[] material = this.verifyPublic.Concat(Encoding.ASCII.GetBytes(this.credentials.pairingId)).Concat(verifier_hap_1["sessionPublicKey"]).ToArray();
                    var ed2 = new Ed25519();
                    ed2.FromPrivateKey(this.privateKey);
                    byte[] signed = ed2.SignMessage(material);
                    Dictionary<byte, byte[]> dic5a = new Dictionary<byte, byte[]>();
                    dic5a.Add(TlvTag.Username, Encoding.ASCII.GetBytes(pairingId));
                    dic5a.Add(TlvTag.Signature, signed);
                    byte[] ps5a = Tlv.Encode(dic5a);
                    (byte[] encryptedTLV1, byte[] encryptedTLV1Hmac) = Encryption.EncryptAndSeal(ps5a, null, Encoding.ASCII.GetBytes("PV-Msg03"), this.verifier_hap_1["encryptionKey"]);
                    Dictionary<byte, byte[]> dic5b = new Dictionary<byte, byte[]>();
                    dic5b.Add(TlvTag.Sequence, new byte[] { 0x03 });
                    dic5b.Add(TlvTag.EncryptedData, encryptedTLV1.Concat(encryptedTLV1Hmac).ToArray());
                    byte[] ps5b = Tlv.Encode(dic5b);
                    body = ps5b;

                    request += "Content-Length: " + ps5b.Length + "\r\n\r\n";

                    break;
                case AUTH_SETUP:
                    request = MakeHead("POST", "/auth-setup", digestInfo);
                    request += "Content-Length:" + "33" + "\r\n\r\n";
                    byte[] auth_fakekey_buf = new byte[] {0x01, // unencrypted
                            0x59, 0x02, 0xed, 0xe9, 0x0d, 0x4e, 0xf2, 0xbd, // static Curve 25519 key
                            0x4c, 0xb6, 0x8a, 0x63, 0x30, 0x03, 0x82, 0x07,
                            0xa9, 0x4d, 0xbd, 0x50, 0xd8, 0xaa, 0x46, 0x5b,
                            0x5d, 0x8c, 0x01, 0x2a, 0x0c, 0x7e, 0x1d, 0x4e};

                    body = auth_fakekey_buf;
                    break;
                case INFO:
                    request = MakeHead("GET", "/info", digestInfo, clear: true);
                    request += "User-Agent: AirPlay/490.16\r\n";
                    request += "Connection: keep-alive\r\n";
                    request += "CSeq: " + NextCSeq() + "\r\n\r\n";

                    break;
                case SETUP_AP2_1:
                    if (_announceId == null)
                    {
                        _announceId = Utils.NumUtil.randomInt(10).ToString();
                    }
                    request = MakeHeadWithURL("SETUP", digestInfo);
                    request += "Content-Type: application/x-apple-binary-plist\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary dict = new NSDictionary();
                        dict.Add("deviceID", "2C:61:F3:B6:64:C1");
                        dict.Add("sessionUUID", "8EB266BA-B741-40C5-8213-4B7A38DF8773");
                        dict.Add("timingPort", _timingPort);
                        dict.Add("timingProtocol", "NTP");
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();
                        body = bpbuf;

                        request += "Content-Length:" + bpbuf.Length + "\r\n\r\n";

                    };
                    break;
                case SETPEERS:
                    request = MakeHeadWithURL("SETPEERS", digestInfo);
                    request += "Content-Type: /peer-list-changed\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSArray dictv = new NSArray {this.hostip,((IPEndPoint)_socket?.Client.LocalEndPoint).Address.MapToIPv4().ToString()};
                        //dictv.Insert(0,this.hostip);
                        //dictv.Insert(1,();
                        bplist.Write(dictv);
                        byte[] bpbuf = memoryStream.ToArray();
                        body = bpbuf;

                        request += "Content-Length:" + bpbuf.Length + "\r\n\r\n";

                    };
                    break;
                case FLUSH:
                    request = MakeHeadWithURL("FLUSH", digestInfo);
                    request += MakeRtpInfo() + "\r\n";

                    break;
                case SETUP_AP2_2:
                    if (_announceId == null)
                    {
                        _announceId = Utils.NumUtil.randomInt(10).ToString();
                    }
                    request = MakeHeadWithURL("SETUP", digestInfo);
                    request += "Content-Type: application/x-apple-binary-plist\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary streams = new NSDictionary();
                        
                        NSDictionary stream = new NSDictionary();
                        stream.Add("audioFormat", 262144); // PCM/44100/16/2 262144
                        stream.Add("audioMode", "default");
                        stream.Add("controlPort", _controlPort);
                        stream.Add("ct", 2);
                        stream.Add("isMedia", true);
                        stream.Add("latencyMax", 88200);
                        stream.Add("latencyMin", 11025);
                        stream.Add("shk", this.credentials.writeKey);
                        stream.Add("spf", 352);
                        stream.Add("sr", 44100);
                        stream.Add("type", 0x60);
                        stream.Add("supportsDynamicStreamID", false);
                        stream.Add("streamConnectionID", _announceId);
                        NSArray array = new NSArray { stream};
                        streams.Add("streams", array);
                        bplist.Write(streams);
                        byte[] bpbuf = memoryStream.ToArray();
                        body = bpbuf;

                        request += "Content-Length:" + bpbuf.Length + "\r\n\r\n";

                    }

                    break;
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

                    if (this.airplay2 != null && this.credentials != null) {
                        this.eventsocket = new TcpClient();

                        this.eventsocket.ConnectAsync(this.hostip, (int) _eventPort);
                        if (_announceId == null)
                        {
                            _announceId = Utils.NumUtil.randomInt(10).ToString();
                        }
                        var nextSeq = _audioOut.LastSeq + 10;
                        var rtpSyncTime = nextSeq * 352 + 2 * 44100;
                        request = MakeHead("RECORD", "rtsp://" + ((IPEndPoint)_socket?.Client.LocalEndPoint).Address.MapToIPv4().ToString() + "/" + _announceId, digestInfo, clear: true);
                        request += "CSeq: " + ++_cseq + "\r\n";
                        request += "User-Agent: AirPlay/490.16" + "\r\n";
                        request += "Client-Instance: " + _dacpId + "\r\n";
                        request += "DACP-ID: " + _dacpId + "\r\n";
                        request += "Active-Remote: " + _activeRemote + "\r\n";
                        request += "X-Apple-ProtocolVersion: 1\r\n";
                        request += "Range: npt=0-\r\n";
                        request += MakeRtpInfo() + "\r\n";

                    } else {
                        request += MakeHeadWithURL("RECORD", digestInfo);
                        request += MakeRtpInfo();
                        request += "Range: npt=0-\r\n\r\n";
                    }
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
                case SETPROGRESS:
                    string hms(int seconds) {
                        return TimeSpan.FromSeconds(seconds).ToString(@"hh\:mm\:ss");
                    }
                    long position = (long)(this.starttime + (this.progress) * (int)(Math.Floor((2 * 44100) / (352 / 125) / 0.71)));
                    long duration = (long)(this.starttime + (this.duration) * (int)(Math.Floor((2 * 44100) / (352 / 125) / 0.71)));
                    string body3 = "progress: " + this.starttime.ToString() + "/" + position.ToString() + "/" + duration.ToString() + "\r\n";
                    request = MakeHeadWithURL("SET_PARAMETER", digestInfo);
                    request +=
                              "Content-Type: text/parameters\r\n" +
                              "Content-Length: " + body3.Length + "\r\n\r\n";
                    request += body3;
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
                    if (this.encryptedChannel && this.credentials != null)
                    {
                        requestBytes = this.credentials.encrypt(requestBytes);
                    }
                    NetworkStream stream = _socket.GetStream();
                    stream.Write(requestBytes, 0, requestBytes.Length);
                    StartTimeout();
                }
                catch (Exception)
                {
                    Cleanup("socket_error");
                }
            }

            var printed_body = (_status == SETART) ? "" : Encoding.UTF8.GetString(body);
            Console.WriteLine($"Sending request: {request} {printed_body}");
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
