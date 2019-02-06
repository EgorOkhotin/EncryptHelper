﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;


namespace SecurityCore.CryptographyProvider.Algos
{
    internal class AES : Algorithm, ICryptographyAlgorithm
    {
        //const int BUFFER_SIZE = 256;
        AesManaged _aes;
        public AES()
        {
            _aes = new AesManaged();
            _aes.KeySize = 256;
            _aes.Mode = CipherMode.CBC;
            _aes.Padding = PaddingMode.None;
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
    }
}