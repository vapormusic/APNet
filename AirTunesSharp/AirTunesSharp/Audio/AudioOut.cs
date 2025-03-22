using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AirTunesSharp.Audio
{
    /// <summary>
    /// C# equivalent of audio_out.js
    /// Manages audio output timing and synchronization
    /// </summary>
    public class AudioOut : EventEmitter
    {
        private int _lastSeq = -1;
        private bool _hasAirTunes = false;
        private System.Timers.Timer _syncTimer;

        public int LastSeq => _lastSeq;

        public AudioOut()
        {
        }

        /// <summary>
        /// Initializes the audio output with devices and circular buffer
        /// </summary>
        /// <param name="devices">Devices manager</param>
        /// <param name="circularBuffer">Circular buffer for audio data</param>
        public void Init(Devices.Devices devices, CircularBuffer circularBuffer)
        {
            Config.RtpTimeRef = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            devices.On("airtunes_devices", args => 
            {
                _hasAirTunes = (bool)args[0];
            });

            devices.On("need_sync", args => 
            {
                // A sync is forced when a new remote device is added
                Emit("need_sync", _lastSeq);
            });

            // Function to send a packet
            void SendPacket(int seq)
            {
                var packet = circularBuffer.ReadPacket();
                // Get MD5 hash of the packet pcm
                // Console.WriteLine(Utils.NumUtil.ComputeMD5(packet.Pcm));

                packet.Seq = seq;
                packet.Timestamp = AirTunesSharp.Utils.NumUtil.Low32(seq * Config.FramesPerPacket + 2 * Config.SamplingRate);

                if (_hasAirTunes && seq % Config.SyncPeriod == 0)
                    Emit("need_sync", seq);

                Emit("packet", packet);

                packet.Release();
            }

            // Start the sync timer
            _syncTimer = new System.Timers.Timer(Config.StreamLatency);
            _syncTimer.Elapsed += (sender, e) => 
            {
                // Calculate elapsed time
                var elapsed = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - Config.RtpTimeRef;

                // Calculate current sequence number
                var currentSeq = (int)Math.Floor(elapsed * Config.SamplingRate / (Config.FramesPerPacket * 1000.0));
                // Console.WriteLine($"Current seq: {currentSeq} compared to last seq: {_lastSeq}");

                // Send packets to catch up
                for (int i = _lastSeq + 1; i <= currentSeq; i++) {
                    SendPacket(i);
                    // Console.WriteLine($"send packet {i}");
                }  

                _lastSeq = currentSeq;
            };
            _syncTimer.AutoReset = true;
            _syncTimer.Start();
        }
    }
}
