using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityCore.CryptographyProvider
{
    static class TransformingUtil
    {
        const int IV = 16;
        const int BLOCK_SIZE = 16;
        internal static (byte[],byte[]) GetIv(byte[] message)
        {
            return GetIv(message, IV);
        }

        internal static byte[] GetEmptyIv()
        {
            return new byte[IV];
        }

        private static (byte[],byte[]) GetIv(byte[] message, int length)
        {
            var iv = message.Take(length).ToArray();
            message = message.Skip(length).ToArray();
            return (iv, message);
        }

        internal static byte[] AlignMessage(byte[] message)
        {
            return AlignMessage(message, BLOCK_SIZE);
        }

        private static byte[] AlignMessage(byte[] message, int blockSize)
        {
            if (message.Length % blockSize != 0)
            {
                var cel = message.Length / blockSize;
                var count = ((cel + 1) * blockSize);
                byte[] buff = new byte[count];
                Array.Copy(message, buff, message.Length);
                message = buff;
            }
            return message;
        }

        internal static byte[] UnAlignMessage(byte[] message)
        {
            int i = message.Length - 1;
            while (message[i] == 0) i--;
            if ((i + 1) % 2 != 0) i++;
            return message.Take(i + 1).ToArray();
        }
    }
}
