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

        public static string ComputeMD5(byte[] data)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(data);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }
    }
}
