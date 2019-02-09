using ExternalEncryption;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecurityCore.CryptographyProvider.Algos
{
    class Serpent : Algorithm, ICryptographyAlgorithm
    {
        SerpentProvider _provider;
        public Serpent()
        {
            _provider = new SerpentProvider();
        }
        public byte[] Encrypt(byte[] message, byte[] key, byte[] iv)
        {
            using (var transform = _provider.CreateEncryptor(key, iv))
            {
                return TransformMessage(transform, message, CryptoStreamMode.Write);
            }
        }

        public byte[] Decrypt(byte[] message, byte[] key, byte[] iv)
        {
            using (var transform = _provider.CreateDecryptor(key, iv))
            {
                return TransformMessage(transform, message, CryptoStreamMode.Read);
            }
        }
    }
}
