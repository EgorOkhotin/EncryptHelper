using ExternalEncryption.NetEncryptionLibrary;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace ExternalEncryption
{
    
    public class SerpentProvider : EncryptProvider
    {
        Serpent _provider;
        
        public SerpentProvider()
        {
            _provider = new Serpent();
            _provider.Padding = PaddingMode.None;
            _provider.BlockSize = 128;
            _provider.KeySize = 128;
            BlockSize = 16;
            KeySize = 16;
            IVSize = 16;
        }
        
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            rgbKey = GetKey(rgbKey);
            rgbIV = GetIv(rgbIV);
            return _provider.CreateDecryptor(rgbKey, rgbIV);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            rgbKey = GetKey(rgbKey);
            rgbIV = GetIv(rgbIV);
            return _provider.CreateEncryptor(rgbKey, rgbIV);
        }
    }


}
