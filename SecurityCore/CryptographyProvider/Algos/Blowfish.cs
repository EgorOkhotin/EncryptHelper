using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using ExternalEncryption;

namespace SecurityCore.CryptographyProvider.Algos
{
    class Blowfish : Algorithm, ICryptographyAlgorithm
    {
        private BlowfishProvider _blowfish;
        public Blowfish()
        {
            _blowfish = new BlowfishProvider();
        }

        public byte[] Encrypt(byte[] message, byte[] key, byte[] iv)
        {
            using (var transform = _blowfish.CreateEncryptor(key, iv))
            {
                return TransformMessage(transform, message, CryptoStreamMode.Write);
            }
        }

        public byte[] Decrypt(byte[] message, byte[] key, byte[] iv)
        {
            using (var transform = _blowfish.CreateDecryptor(key, iv))
            {
                return TransformMessage(transform, message, CryptoStreamMode.Read);
            }
        }
    }
}
