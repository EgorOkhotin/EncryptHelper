using System;
using System.Security.Cryptography;
using ExternalEncryption.NetEncryptionLibrary;

namespace ExternalEncryption
{
    public class BlowfishProvider
    {
        BlowfishCrypto _provider;
        public BlowfishProvider()
        {
            _provider = new BlowfishCrypto();
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
