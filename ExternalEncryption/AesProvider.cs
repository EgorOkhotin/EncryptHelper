using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExternalEncryption
{
    public class AesProvider : EncryptProvider
    {
        AesManaged _provider;
        public AesProvider()
        {
            _provider = new AesManaged();
            _provider.KeySize = _provider.LegalKeySizes.Last().MaxSize;
            _provider.BlockSize = _provider.LegalBlockSizes.Last().MaxSize;
            _provider.Mode = CipherMode.CBC;
            _provider.Padding = PaddingMode.None;
            BlockSize = 16;
            IVSize = 16;
            KeySize = 32;
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
