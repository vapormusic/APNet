using System;
using System.Collections.Generic;

namespace AirTunesSharp.Network
{
    /// <summary>
    /// C# equivalent of ntp.js
    /// Provides NTP timestamp functionality
    /// </summary>
    public class Ntp
    {
        private readonly long _timeRef;

        public Ntp()
        {
            _timeRef = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)Config.NtpEpoch * 1000;
        }

        /// <summary>
        /// Generates an NTP timestamp
        /// </summary>
        /// <returns>Byte array containing the NTP timestamp</returns>
        public byte[] Timestamp()
        {
            long time = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - _timeRef;
            int sec = (int)(time / 1000);
            
            long msec = time - sec * 1000;
            uint ntpMsec = (uint)Math.Floor(msec * 4294967.296);
            
            byte[] ts = new byte[8];
            
            BitConverter.GetBytes(sec).CopyTo(ts, 0);
            BitConverter.GetBytes(ntpMsec).CopyTo(ts, 4);
            
            // Convert to big-endian if on little-endian system
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(ts, 0, 4);
                Array.Reverse(ts, 4, 4);
            }
            
            return ts;
        }
    }
    
    /// <summary>
    /// Singleton instance of the NTP class
    /// </summary>
    public static class NtpInstance
    {
        private static readonly Ntp Instance = new Ntp();
        
        public static byte[] Timestamp() => Instance.Timestamp();
    }
}
