using ExternalEncryption;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;


namespace SecurityCore.CryptographyProvider.Algos
{
    internal class AES : Algorithm, ICryptographyAlgorithm
    {
        AesProvider _aes;
        public AES()
        {
            _aes = new AesProvider();
        }

        public byte[] Encrypt(byte[] message, byte[] key, byte[] iv)
        {
            using (var transform = _aes.CreateEncryptor(key, iv))
            {
                return TransformMessage(transform, message, CryptoStreamMode.Write);
            }
        }

        public byte[] Decrypt(byte[] message, byte[] key, byte[] iv)
        {
            using(var transform = _aes.CreateDecryptor(key, iv))
            {
                return TransformMessage(transform, message, CryptoStreamMode.Read);
            }
        }

        public int KeyByteSize => _aes.KeySize;
        public int BlockByteSize => _aes.KeySize;
    }
}
