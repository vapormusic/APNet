using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace AirTunesSharp.Network
{
    /// <summary>
    /// C# equivalent of udp_servers.js
    /// Manages UDP sockets for control and timing
    /// </summary>
    public class UdpServers : EventEmitter
    {
        // Status constants
        private const int UNBOUND = 0;
        private const int BINDING = 1;
        private const int BOUND = 2;

        private int _status = UNBOUND;
        private readonly UdpEndpoint _control;
        private readonly UdpEndpoint _timing;
        private readonly List<string> _hosts = new();
        
        public UdpEndpoint Control => _control;
        public UdpEndpoint Timing => _timing;

        public UdpServers()
        {
            _control = new UdpEndpoint
            {
                Socket = null,
                Port = null,
                Name = "control"
            };

            _timing = new UdpEndpoint
            {
                Socket = null,
                Port = null,
                Name = "timing"
            };
        }

        /// <summary>
        /// Binds UDP sockets to available ports
        /// </summary>
        /// <param name="host">Host to bind to</param>
        public void Bind(string host)
        {
            _hosts.Add(host);

            switch (_status)
            {
                case BOUND:
                    Task.Run(() => Emit("ports", null, _control, _timing));
                    return;
                case BINDING:
                    return;
            }

            _status = BINDING;

            // Create timing socket
            _timing.Socket = new UdpClient(AddressFamily.InterNetwork);
            _timing.Socket.EnableBroadcast = true;

            // Create control socket
            _control.Socket = new UdpClient(AddressFamily.InterNetwork);
            _control.Socket.EnableBroadcast = true;

            
           // Find open ports
            BindPorts();

            // Handle timing messages
            Task.Run(async () =>
            {
                while (_status != UNBOUND && _timing.Socket != null)
                {
                    try
                    {
                        var result = await _timing.Socket.ReceiveAsync();
                        var rinfo = new { address = result.RemoteEndPoint.Address.ToString(), port = result.RemoteEndPoint.Port };

                        // Only listen and respond on own hosts
                        if (!_hosts.Contains(rinfo.address)) continue;

                        var msg = result.Buffer;
                        if (msg.Length < 32) continue;

                        var ts1 = BitConverter.ToUInt32(new byte[] { msg[27], msg[26], msg[25], msg[24] }, 0);
                        var ts2 = BitConverter.ToUInt32(new byte[] { msg[31], msg[30], msg[29], msg[28] }, 0);

                        var reply = new byte[32];
                        reply[0] = 0x80;
                        reply[1] = 0xd3;
                        reply[2] = 0x00;
                        reply[3] = 0x07;
                        // bytes 4-7 are zero

                        // Copy ts1 and ts2 to reply
                        BitConverter.GetBytes(ts1).CopyTo(reply, 8);
                        BitConverter.GetBytes(ts2).CopyTo(reply, 12);

                        // Get NTP timestamp
                        var ntpTime = NtpInstance.Timestamp();
                        Buffer.BlockCopy(ntpTime, 0, reply, 16, 8);
                        Buffer.BlockCopy(ntpTime, 0, reply, 24, 8);

                        // Convert to big-endian if on little-endian system
                        if (BitConverter.IsLittleEndian)
                        {
                            for (int i = 8; i < 16; i += 4)
                                Array.Reverse(reply, i, 4);
                            for (int i = 16; i < 32; i += 4)
                                Array.Reverse(reply, i, 4);
                        }
                        Console.WriteLine("Replying to timing request");
                        await _timing.Socket.SendAsync(reply, reply.Length, new IPEndPoint(IPAddress.Parse(rinfo.address), rinfo.port));
                    }
                    catch (Exception)
                    {
                        // Handle socket errors
                        // if (_status == UNBOUND) break;
                    }
                }
            });




            // Handle control messages
            Task.Run(async () =>
            {
                while (_status != UNBOUND && _control.Socket != null)
                {
                    try
                    {          
                        var result = await _control.Socket.ReceiveAsync();
                        var rinfo = new { address = result.RemoteEndPoint.Address.ToString(), port = result.RemoteEndPoint.Port };

                        // Only listen for own hosts
                        if (!_hosts.Contains(rinfo.address)) continue;

                        var msg = result.Buffer;
                        if (msg.Length < 8) continue;

                        // Extract control information
                        ushort serverSeq = BitConverter.ToUInt16(new byte[] { msg[3], msg[2] }, 0);
                        ushort missedSeq = BitConverter.ToUInt16(new byte[] { msg[5], msg[4] }, 0);
                        ushort count = BitConverter.ToUInt16(new byte[] { msg[7], msg[6] }, 0);

                        // Debug logging could be added here
                        // Send blank reply
                        var reply = new byte[8];
                        await _control.Socket.SendAsync(reply, reply.Length, new IPEndPoint(IPAddress.Parse(rinfo.address), rinfo.port));
                    }
                    catch (Exception)
                    {
                        // Handle socket errors
                        // if (_status == UNBOUND) break;
                    }
                }
            });


        }

        private async void BindPorts()
        {
            var toBind = new List<UdpEndpoint> { _control, _timing };
            int currentPort = Config.UdpDefaultPort;
            bool success = true;

            while (toBind.Count > 0 && success)
            {
                var nextPort = toBind[0];
                try
                {
                    nextPort.Socket.Client.Bind(new IPEndPoint(IPAddress.Any, currentPort));
                    nextPort.Port = currentPort;
                    toBind.RemoveAt(0);
                    currentPort++;
                }
                catch (SocketException)
                {
                    // Port in use, try next one
                    currentPort++;
                    if (currentPort > 65535)
                    {
                        success = false;
                        break;
                    }
                }
                catch (Exception)
                {
                    success = false;
                    break;
                }
            }

            if (!success)
            {
                Close();
                Emit("ports", new Exception("Failed to bind UDP ports"));
            }
            else
            {
                _status = BOUND;
                Emit("ports", null, _control, _timing);
            }
        }

        /// <summary>
        /// Closes UDP sockets
        /// </summary>
        public void Close()
        {
            if (_status == UNBOUND)
                return;

            _status = UNBOUND;

            _timing.Socket?.Close();
            _timing.Socket = null;

            _control.Socket?.Close();
            _control.Socket = null;
        }

        /// <summary>
        /// Sends a control sync packet to a device
        /// </summary>
        /// <param name="seq">Sequence number</param>
        /// <param name="dev">Device to send to</param>
        public void SendControlSync(int seq, dynamic dev)
        {
            if (_status != BOUND)
                return;

            var packet = new byte[20];

            packet[0] = 0x80;
            packet[1] = 0xd4;
            packet[2] = 0x00;
            packet[3] = 0x07;

            uint timestamp = Utils.NumUtil.Low32(seq * Config.FramesPerPacket);
            byte[] timestampBytes = BitConverter.GetBytes(timestamp);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(timestampBytes);
            Buffer.BlockCopy(timestampBytes, 0, packet, 4, 4);

            var ntpTime = NtpInstance.Timestamp();
            Buffer.BlockCopy(ntpTime, 0, packet, 8, 8);

            uint rtpTimestamp = Utils.NumUtil.Low32(seq * Config.FramesPerPacket + Config.SamplingRate * 2);
            byte[] rtpTimestampBytes = BitConverter.GetBytes(rtpTimestamp);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(rtpTimestampBytes);
            Buffer.BlockCopy(rtpTimestampBytes, 0, packet, 16, 4);

            _control.Socket.Send(packet, packet.Length, new IPEndPoint(IPAddress.Parse(dev.Host), dev.ControlPort));
        }
    }

    /// <summary>
    /// Represents a UDP endpoint with socket and port
    /// </summary>
    public class UdpEndpoint
    {
        public UdpClient Socket { get; set; }
        public int? Port { get; set; }
        public string Name { get; set; }
    }
}
