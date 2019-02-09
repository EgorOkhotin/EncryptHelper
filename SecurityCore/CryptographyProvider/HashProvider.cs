using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecurityCore.CryptographyProvider
{
    class HashProvider : IHashProvider
    {
        HMACSHA512 _hash;
        public HashProvider()
        {
            _hash = new HMACSHA512();
        }

        private byte[] Hash(byte[] arr)
        {
            return _hash.ComputeHash(arr);
        }

        string IHashProvider.Hash(byte[] data)
        {
            var result =  Convert.ToBase64String(Hash(data));
            return result;
        }
    }
}
