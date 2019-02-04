using SecurityCore.CryptographyProvider.Algos;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.CryptographyProvider
{
    class VernammEncryption : ICryptographyProvider
    {
        readonly ICryptographyAlgorithm _vernamm;
        string _keyHash;

        public VernammEncryption(ICryptographyAlgorithm alg)
        {
            _vernamm = alg;
        }

        public void SetKey(string keyHash)
        {
            _keyHash = keyHash;
        }

        public byte[] Decrypt(byte[] message)
        {
            var result = _vernamm.Decrypt(message, GetKey(_keyHash), null);
            return result;
        }

        public byte[] Encrypt(byte[] message)
        {
            var result = _vernamm.Encrypt(message, GetKey(_keyHash), null);
            return result;
        }

        private byte[] GetKey(string name)
        {
            throw new NotImplementedException();
        }
    }
}
