using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AirTunesSharp.Audio
{
    /// <summary>
    /// C# equivalent of circular_buffer.js
    /// Implements a circular buffer for audio data
    /// </summary>
    public class CircularBuffer : EventEmitter
    {
        // Status constants
        private const int WAITING = 0;
        private const int FILLING = 1;
        private const int NORMAL = 2;
        private const int DRAINING = 3;
        private const int ENDING = 4;
        private const int ENDED = 5;

        private readonly PacketPool _packetPool;
        private readonly int _maxSize;
        private readonly int _packetSize;
        private readonly List<byte[]> _buffers = new();
        private int _currentSize;
        private int _status;
        private bool _muted;

        public bool Writable { get; private set; }

        public CircularBuffer(int packetsInBuffer, int packetSize)
        {
            _packetPool = new PacketPool();
            _maxSize = packetsInBuffer * packetSize;
            _packetSize = packetSize;
            Writable = true;
            _muted = false;
            _currentSize = 0;
            _status = WAITING;
        }

        /// <summary>
        /// Writes data to the buffer
        /// </summary>
        /// <param name="chunk">Data to write</param>
        /// <returns>True if more data can be written, false if buffer is full</returns>
        public bool Write(byte[] chunk)
        {
            _buffers.Add(chunk);
            _currentSize += chunk.Length;

            if (_status == ENDING || _status == ENDED)
                throw new InvalidOperationException("Cannot write in buffer after closing it");

            if (_status == WAITING)
            {
                // Notify when we receive the first chunk
                Emit("status", "buffering");
                _status = FILLING;
            }

            if (_status == FILLING && _currentSize > _maxSize / 2)
            {
                _status = NORMAL;
                Emit("status", "playing");
            }

            if (_currentSize >= _maxSize / 2)
            {
                _status = DRAINING;
                return false;
            }
            else
            {
                return true;
            }
        }

        /// <summary>
        /// Reads a packet from the buffer
        /// </summary>
        /// <returns>A Packet instance</returns>
        public Packet ReadPacket()
        {
            var packet = _packetPool.GetPacket();

            // Play silence until buffer is filled enough
            if (_status != ENDING && _status != ENDED &&
                (_status == FILLING || _currentSize < _packetSize))
            {
                Array.Clear(packet.Pcm, 0, packet.Pcm.Length);

                if (_status != FILLING && _status != WAITING)
                {
                    _status = FILLING;
                    Emit("status", "buffering");
                }
            }
            else
            {
                int offset = 0;
                int remaining = _packetSize;

                // Fill a whole packet with data
                while (remaining > 0)
                {
                    // Pad packet with silence if buffer is empty
                    if (_buffers.Count == 0)
                    {
                        Array.Clear(packet.Pcm, offset, packet.Pcm.Length - offset);
                        remaining = 0;
                        break;
                    }



                    if (_buffers[0].Length <= remaining)
                    {
                        // Pop the whole buffer from the queue
                        Buffer.BlockCopy(_buffers[0], 0, packet.Pcm, offset, _buffers[0].Length);
                        offset += _buffers[0].Length;
                        remaining -= _buffers[0].Length;
                        _buffers.RemoveAt(0);
                    }
                    else
                    {
                        try {
                            // Console.WriteLine($"md5 first: {Utils.NumUtil.ComputeMD5(_buffers[0])}");

                            // First buffer contains enough data to fill a packet: slice it
                            Buffer.BlockCopy(_buffers[0], 0, packet.Pcm, offset, remaining);
                            byte[] newBuffer = new byte[_buffers[0].Length - remaining];
                            Buffer.BlockCopy(_buffers[0], remaining, newBuffer, 0, _buffers[0].Length - remaining);
                            _buffers[0] = newBuffer;
                            remaining = 0;
                            offset += remaining;
                        } catch (Exception e) {
                    //         Console.WriteLine(e);
                        }
                        // Console.WriteLine($"md5 first: {Utils.NumUtil.ComputeMD5(_buffers[0])}");
                        // Console.WriteLine(Convert.ToHexString(packet.Pcm));
                        // Console.WriteLine("Buffer slice, remaining: " + _buffers[0].Length);
                    }
                }

                _currentSize -= _packetSize;

                // Emit 'end' only once
                if (_status == ENDING && _currentSize <= 0)
                {
                    _status = ENDED;
                    _currentSize = 0;
                    Emit("status", "end");
                }

                // Notify that the buffer now has enough room if needed
                if (_status == DRAINING && _currentSize < _maxSize )
                {
                    _status = NORMAL;
                    Emit("drain");
                }
            }

            if (_muted)
                Array.Clear(packet.Pcm, 0, packet.Pcm.Length);

            return packet;
        }

        /// <summary>
        /// Signals the end of data
        /// </summary>
        public void End()
        {
            // Flush the buffer if it was filling
            if (_status == FILLING)
                Emit("status", "playing");

            _status = ENDING;
        }

        /// <summary>
        /// Resets the buffer to initial state
        /// </summary>
        public void Reset()
        {
            _buffers.Clear();
            _currentSize = 0;
            _status = WAITING;
        }
    }
}
