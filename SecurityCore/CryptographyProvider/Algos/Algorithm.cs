using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace SecurityCore.CryptographyProvider.Algos
{
    internal class Algorithm
    {
        protected const int BUFFER_SIZE = 256;
        protected byte[] TransformMessage(ICryptoTransform transform, byte[] message, CryptoStreamMode mode)
        {
            MemoryStream memoryStream;
            if (mode == CryptoStreamMode.Read)
            {
                memoryStream = new MemoryStream(message);
            }
            else memoryStream = new MemoryStream();

            using (memoryStream)
            {
                using (var cryptoStream = new CryptoStream(memoryStream, transform, mode))
                {
                    return TransformBytes(cryptoStream, message, mode, memoryStream);
                }
            }
        }

        private byte[] TransformBytes(CryptoStream cryptoStream, byte[] array, CryptoStreamMode mode, MemoryStream baseCryptoStream)
        {
            var result = new List<byte>(BUFFER_SIZE * 4);
            if (mode == CryptoStreamMode.Read)
            {
                //cryptoStream.Flush();
                //baseCryptoStream.Write(array, 0, array.Length);
                
                byte[] buffer = new byte[Extensions.DATABLOCK_LENGTH];
                int count = 0;
                do
                {
                    count = cryptoStream.Read(buffer, 0, buffer.Length);
                    result.AddRange(buffer.Take(count));
                } while (count != 0);
            }
            else
            {
                array = AlignMessage(array);
                cryptoStream.Write(array, 0, array.Length);
                result.AddRange(baseCryptoStream.ToArray());
            }
            return result.ToArray();
        }

        private byte[] AlignMessage(byte[] message)
        {
            if (message.Length % Extensions.DATABLOCK_LENGTH != 0)
            {
                var cel = message.Length / Extensions.DATABLOCK_LENGTH;
                var count = ((cel + 1) * Extensions.DATABLOCK_LENGTH);
                byte[] buff = new byte[count];
                Array.Copy(message, buff, message.Length);
                message = buff;
            }
            return message;
        }
    }
}
