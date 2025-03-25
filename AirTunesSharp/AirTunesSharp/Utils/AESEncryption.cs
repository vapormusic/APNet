using System;
using System.IO;
using System.Security.Cryptography;

namespace AirTunesSharp.Utils
{
    public static class AirTunesEncryption
    {
        // AirTunes specific initialization vector and key
        private static readonly byte[] Iv = new byte[] 
        { 0x78, 0xf4, 0x41, 0x2c, 0x8d, 0x17, 0x37, 0x90, 0x2b, 0x15, 0xa6, 0xb3, 0xee, 0x77, 0x0d, 0x67 };

        private static readonly byte[] Key = new byte[] 
        { 0x14, 0x49, 0x7d, 0xcc, 0x98, 0xe1, 0x37, 0xa8, 0x55, 0xc1, 0x45, 0x5a, 0x6b, 0xc0, 0xc9, 0x79 };

        /// <summary>
        /// Encrypts ALAC data using AES-128-CBC encryption, with no padding
        /// </summary>
        /// <param name="alacData">The ALAC data to encrypt</param>
        /// <returns>Encrypted data with any remainder preserved as plain text</returns>
        public static byte[] EncryptAES(byte[] alacData)
        {

            int remainder = alacData.Length % 16;
            int endOfEncodedData = alacData.Length - remainder;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = Iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None; // Equivalent to `setAutoPadding(false)`

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] encryptedData = new byte[endOfEncodedData];
                    
                    for (int i = 0; i <= endOfEncodedData - 16; i += 16)
                    {
                        encryptor.TransformBlock(alacData, i, 16, encryptedData, i);
                    }

                    return encryptedData.Concat(alacData.Skip(endOfEncodedData)).ToArray();
                }
            }
        }
    }
}