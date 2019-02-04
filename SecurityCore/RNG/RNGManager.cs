using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecurityCore.RNG
{
    class RNGManager
    {
        static RNGCryptoServiceProvider _provider;
        public RNGManager()
        {
            _provider = new RNGCryptoServiceProvider();
        }

        public void GetBytes(byte[] array)
        {
            _provider.GetBytes(array);
        }

        public byte GetByte()
        {
            var result = new byte[1];
            _provider.GetBytes(result);
            return result[0];
        }
    }
}
