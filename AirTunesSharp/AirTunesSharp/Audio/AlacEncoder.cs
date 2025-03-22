using System;
using System.Runtime.InteropServices;

namespace AirTunesSharp.Audio
{
    /// <summary>
    /// Provides methods for converting PCM audio data to ALAC format
    /// </summary>
    public static class AlacEncoder
    {
        /// <summary>
        /// Converts PCM data to ALAC format
        /// </summary>
        /// <param name="pcmData">PCM audio data</param>
        /// <param name="frames">Number of frames to encode</param>
        /// <param name="bsize">Block size</param>
        /// <returns>ALAC encoded data</returns>
        public static byte[] PcmToAlac(byte[] pcmData, int frames, int bsize)
        {
            // Ensure frames doesn't exceed bsize
            frames = Math.Min(frames, bsize);

            // Allocate output buffer (bsize * 4 + 16 bytes)
            byte[] output = new byte[bsize * 4 + 16];
            int outputIndex = 0;

            // Cast PCM data to uint32 array for processing
            uint[] inputSamples = new uint[pcmData.Length / 4];
            Buffer.BlockCopy(pcmData, 0, inputSamples, 0, pcmData.Length);

            // Write header
            output[outputIndex++] = (1 << 5);
            output[outputIndex++] = 0;
            output[outputIndex++] = (byte)((1 << 4) | (1 << 1) | ((bsize & 0x80000000) >> 31)); // b31
            output[outputIndex++] = (byte)(((bsize & 0x7f800000) << 1) >> 24);  // b30--b23
            output[outputIndex++] = (byte)(((bsize & 0x007f8000) << 1) >> 16);  // b22--b15
            output[outputIndex++] = (byte)(((bsize & 0x00007f80) << 1) >> 8);   // b14--b7
            
            // b6--b0 + LB1 b7
            output[outputIndex] = (byte)(((bsize & 0x0000007f) << 1));
            output[outputIndex++] |= (byte)((inputSamples[0] & 0x00008000) >> 15);

            // Process all frames except the last one
            for (int i = 0; i < frames - 1; i++)
            {
                uint currentSample = inputSamples[i];
                uint nextSample = inputSamples[i + 1];

                // LB1 b6--b0 + LB0 b7
                output[outputIndex++] = (byte)((currentSample & 0x00007f80) >> 7);
                
                // LB0 b6--b0 + RB1 b7
                output[outputIndex++] = (byte)(((currentSample & 0x0000007f) << 1) | ((currentSample & 0x80000000) >> 31));
                
                // RB1 b6--b0 + RB0 b7
                output[outputIndex++] = (byte)((currentSample & 0x7f800000) >> 23);
                
                // RB0 b6--b0 + next LB1 b7
                output[outputIndex++] = (byte)(((currentSample & 0x007f0000) >> 15) | ((nextSample & 0x00008000) >> 15));
            }

            // Process the last sample
            uint lastSample = inputSamples[frames - 1];
            
            // LB1 b6--b0 + LB0 b7
            output[outputIndex++] = (byte)((lastSample & 0x00007f80) >> 7);
            
            // LB0 b6--b0 + RB1 b7
            output[outputIndex++] = (byte)(((lastSample & 0x0000007f) << 1) | ((lastSample & 0x80000000) >> 31));
            
            // RB1 b6--b0 + RB0 b7
            output[outputIndex++] = (byte)((lastSample & 0x7f800000) >> 23);
            
            // RB0 b6--b0 + next LB1 b7
            output[outputIndex++] = (byte)((lastSample & 0x007f0000) >> 15);

            // Fill remaining space with zeros when frames < bsize
            int remainingBytes = (bsize - frames) * 4;
            for (int i = 0; i < remainingBytes; i++)
            {
                output[outputIndex++] = 0;
            }

            // Add frame footer
            output[outputIndex - 1] |= 1;
            output[outputIndex] = (byte)((7 >> 1) << 6);

            // Create final output array of the exact size needed
            int finalSize = outputIndex + 1;
            byte[] finalOutput = new byte[finalSize];
            Buffer.BlockCopy(output, 0, finalOutput, 0, finalSize);

            return finalOutput;
        }
    }
}
