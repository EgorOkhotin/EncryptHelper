﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using ExternalEncryption.NetEncryptionLibrary;

namespace ExternalEncryption
{
    public class TwofishProvider : EncryptProvider
    {
        TwofishManaged _provider;
        public TwofishProvider()
        {
            _provider = new TwofishManaged();
            _provider.KeySize = 256;
            _provider.BlockSize = 128;
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
