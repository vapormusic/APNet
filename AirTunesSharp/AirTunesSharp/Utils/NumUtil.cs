using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace AirTunesSharp.Utils
{
    /// <summary>
    /// C# equivalent of num_util.js
    /// Provides utility functions for number operations and random value generation
    /// </summary>
    public static class NumUtil
    {
        private static readonly Random Random = new Random();

        /// <summary>
        /// Generates a random hexadecimal string of specified length
        /// </summary>
        /// <param name="length">Number of bytes to generate</param>
        /// <returns>Hexadecimal string</returns>
        public static string RandomHex(int length)
        {
            byte[] buffer = new byte[length];
            Random.NextBytes(buffer);
            return BitConverter.ToString(buffer).Replace("-", "").ToLower();
        }

        /// <summary>
        /// Generates a random Base64 string of specified length
        /// </summary>
        /// <param name="length">Number of bytes to generate</param>
        /// <returns>Base64 string without padding</returns>
        public static string RandomBase64(int length)
        {
            byte[] buffer = new byte[length];
            Random.NextBytes(buffer);
            return Convert.ToBase64String(buffer).Replace("=", "");
        }

        /// <summary>
        /// Generates a random integer with specified number of digits
        /// </summary>
        /// <param name="digits">Number of digits</param>
        /// <returns>Random integer</returns>
        public static int RandomInt(int digits)
        {
            return Random.Next((int)Math.Pow(10, digits - 1), (int)Math.Pow(10, digits));
        }

        /// <summary>
        /// Returns the lower 16 bits of an integer
        /// </summary>
        /// <param name="value">Input value</param>
        /// <returns>Lower 16 bits as ushort</returns>
        public static ushort Low16(int value)
        {
            return (ushort)(value % 65536);
        }

        /// <summary>
        /// Returns the lower 32 bits of a long integer
        /// </summary>
        /// <param name="value">Input value</param>
        /// <returns>Lower 32 bits as uint</returns>
        public static uint Low32(long value)
        {
            return (uint)(value % 4294967296);
        }

        /// <summary>
        /// Computes the MD5 hash of a byte array
        /// </summary>
        /// <param name="data">Input data</param>
        /// <returns>MD5 hash as hexadecimal string</returns>

        public static string ComputeMD5(byte[] data)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(data);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        /// <summary>
        /// Get byte array from hexadecimal string
        /// </summary>
        /// <param name="hex">Hexadecimal string</param>
        /// <returns>Byte array</returns>
        public static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        /// <summary>
        /// Unpacks a 2-byte little-endian unsigned short from a big-endian byte array
        /// similar to struct.unpack('H', data)
        /// </summary>
        /// <param name="data">Input data</param>
        /// <param name="offset">Offset in the array</param>
        /// <returns>Unpacked value</returns>
        public static ushort UnPackH(byte[] data, int offset)
        {
            if (!BitConverter.IsLittleEndian)
                return BitConverter.ToUInt16(data.Reverse().ToArray(), offset);
            else
            return BitConverter.ToUInt16(data.Reverse().ToArray(), offset);
        }

        /// <summary>
        /// Packs a 2-byte little-endian unsigned short into a big-endian byte array
        /// similar to struct.pack('H', value)
        /// </summary>
        /// <param name="value">Value to pack</param>
        /// <returns>Packed byte array</returns>

        public static byte[] PackH(ushort value)
        {
            byte[] data = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian)
                return data.Reverse().ToArray();
            else
                return data;
        }
        

    }
}
