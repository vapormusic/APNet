using System;
using System.IO;

namespace AirTunesSharp.Audio
{
    /// <summary>
    /// C# equivalent of packet_pool.js
    /// Implements an object pool for audio packets to reduce memory allocations
    /// </summary>
    public class PacketPool
    {
        private readonly Packet[] _pool = {};

        /// <summary>
        /// Gets a packet from the pool or creates a new one if the pool is empty
        /// </summary>
        /// <returns>A Packet instance</returns>
        public Packet GetPacket()
        {
            if (_pool.Length > 0)
            {
                var packet = _pool[0];
                packet.Retain();
                return packet;
            }
            
            return new Packet(this);
        }

        /// <summary>
        /// Returns a packet to the pool
        /// </summary>
        /// <param name="packet">The packet to release</param>
        public void Release(Packet packet)
        {
            _pool.Append(packet);   
        }
    }

    /// <summary>
    /// Represents an audio packet with reference counting
    /// </summary>
    public class Packet
    {
        private readonly PacketPool _pool;
        private int _refCount;
        
        /// <summary>
        /// Sequence number of the packet
        /// </summary>
        public int? Seq { get; set; }
        
        /// <summary>
        /// PCM audio data
        /// </summary>
        public byte[] Pcm { get; }
        
        /// <summary>
        /// Timestamp for RTP
        /// </summary>
        public uint Timestamp { get; set; }

        public Packet(PacketPool pool)
        {
            _pool = pool;
            _refCount = 1;
            Seq = null;
            Pcm = new byte[Config.PacketSize];
        }

        /// <summary>
        /// Increments the reference count
        /// </summary>
        public void Retain()
        {
            _refCount++;
        }

        /// <summary>
        /// Decrements the reference count and returns the packet to the pool if count reaches zero
        /// </summary>
        public void Release()
        {
            _refCount--;

            if (_refCount == 0)
            {
                Seq = null;
                _pool.Release(this);
            }
        }
    }
}
