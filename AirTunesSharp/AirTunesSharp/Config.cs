using System;
using System.Collections.Generic;

namespace AirTunesSharp
{
    /// <summary>
    /// C# equivalent of config.js
    /// Contains configuration settings for the AirTunes implementation
    /// </summary>
    public static class Config
    {
        public static string UserAgent { get; set; } = "Radioline/1.4.0";
        public static int UdpDefaultPort { get; set; } = 6000;
        public static int FramesPerPacket { get; set; } = 352;
        public static int ChannelsPerFrame { get; set; } = 2;
        public static int BitsPerChannel { get; set; } = 16;
        public static int PacketSize { get; set; } = 352 * 2 * 2; // frames*channels*bytes
        public static int PacketsInBuffer { get; set; } = 200;
        public static int CoreAudioMinLevel { get; set; } = 5;
        public static int CoreAudioCheckPeriod { get; set; } = 2000;
        public static int CoreAudioPreload { get; set; } = 1408 * 50;
        public static int SamplingRate { get; set; } = 44100;
        public static int SyncPeriod { get; set; } = 126;
        public static int StreamLatency { get; set; } = 50;
        public static int RtspTimeout { get; set; } = 120000;
        public static int RtspHeartbeat { get; set; } = 15000;
        public static long RtpTimeRef { get; set; } = 0;
        public static int DeviceMagic { get; set; }
        public static uint NtpEpoch { get; set; } = 0x83aa7e80;
        public static string IvBase64 { get; set; } = "ePRBLI0XN5ArFaaz7ncNZw";
        public static string RsaAeskeyBase64 { get; set; } = "VjVbxWcmYgbBbhwBNlCh3K0CMNtWoB844BuiHGUJT51zQS7SDpMnlbBIobsKbfEJ3SCgWHRXjYWf7VQWRYtEcfx7ejA8xDIk5PSBYTvXP5dU2QoGrSBv0leDS6uxlEWuxBq3lIxCxpWO2YswHYKJBt06Uz9P2Fq2hDUwl3qOQ8oXb0OateTKtfXEwHJMprkhsJsGDrIc5W5NJFMAo6zCiM9bGSDeH2nvTlyW6bfI/Q0v0cDGUNeY3ut6fsoafRkfpCwYId+bg3diJh+uzw5htHDyZ2sN+BFYHzEfo8iv4KDxzeya9llqg6fRNQ8d5YjpvTnoeEQ9ye9ivjkBjcAfVw";

        static Config()
        {
            // Initialize random device magic
            DeviceMagic = AirTunesSharp.Utils.NumUtil.RandomInt(9);
        }
    }
}
