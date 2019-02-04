using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using ExternalEncryption.NetEncryptionLibrary;

namespace ExternalEncryption
{
    public class TwofishProvider
    {
        Twofish _provider;
        public TwofishProvider()
        {
            _provider = new Twofish();
        }
        public ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return _provider.CreateDecryptor(rgbKey, rgbIV);
        }

        public ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return _provider.CreateEncryptor(rgbKey, rgbIV);
        }
    }
}
