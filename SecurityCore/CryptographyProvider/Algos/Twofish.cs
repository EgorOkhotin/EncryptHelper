using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using ExternalEncryption;

namespace SecurityCore.CryptographyProvider.Algos
{
    class Twofish : Algorithm, ICryptographyAlgorithm
    {
        TwofishProvider _twofish;

        public Twofish()
        {
            _twofish = new TwofishProvider();
        }
        
        public byte[] Encrypt(byte[] message, byte[] key, byte[] iv)
        {
            using (var encryptor = _twofish.CreateEncryptor(key, iv))
            {
                return TransformMessage(encryptor, message, CryptoStreamMode.Write);
            }
        }

        public byte[] Decrypt(byte[] message, byte[] key, byte[] iv)
        {
            using (var decryptor = _twofish.CreateDecryptor(key, iv))
            {
                return TransformMessage(decryptor, message, CryptoStreamMode.Read);
            }
        }
    }
}
