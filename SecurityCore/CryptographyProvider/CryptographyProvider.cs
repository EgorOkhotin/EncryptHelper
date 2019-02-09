using SecurityCore.RNG;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.CryptographyProvider
{
    abstract class CryptographyProvider : ICryptographyProvider
    {
        RNGManager _rng;
        List<string> _keyHashes;

        public CryptographyProvider()
        {
            _rng = new RNGManager();
            _keyHashes = new List<string>();
        }

        public abstract byte[] Decrypt(byte[] message);
        public abstract byte[] Encrypt(byte[] message);

        protected RNGManager RNG => _rng;
        protected List<string> KeyHashes => _keyHashes;

    }
}
