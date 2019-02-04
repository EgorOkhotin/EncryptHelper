using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.CryptographyProvider.Algos
{
    class Vernamm : ICryptographyAlgorithm
    {
        public byte[] Decrypt(byte[] message, byte[] key, byte[] iv = null)
        {
            return XORArrays(message, key);
        }

        public byte[] Encrypt(byte[] message, byte[] key, byte[] iv = null)
        {
            return XORArrays(message, key);
        }

        private byte[] XORArrays(byte[] messageArray, byte[] keyArray)
        {
            for (int i = 0; i < messageArray.Length; i++)
            {
                messageArray[i] ^= keyArray[i];
                keyArray[i] = 0;
            }

            return messageArray;
        }
    }
}
