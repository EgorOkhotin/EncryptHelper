using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary
{
    internal class Serpent : SymmetricAlgorithm
    {
        public Serpent() : base()
        {
        }
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey.Length != (SerpentEngine.BLOCK_BIT_SIZE/8) || rgbIV.Length != (SerpentEngine.BLOCK_BIT_SIZE / 8))
                throw new ArgumentException("Illegal key or iv array size");
            return (ICryptoTransform)new SerpentEngine(rgbKey, false);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey.Length != (SerpentEngine.BLOCK_BIT_SIZE / 8) || rgbIV.Length != (SerpentEngine.BLOCK_BIT_SIZE / 8))
                throw new ArgumentException("Illegal key or iv array size");
            return (ICryptoTransform)new SerpentEngine(rgbKey, true);
        }

        public override void GenerateIV()
        {
            throw new NotImplementedException();
        }

        public override void GenerateKey()
        {
            throw new NotImplementedException();
        }

        public override int BlockSize { get; set; }
        public override int KeySize { get; set; }
        public override PaddingMode Padding { get; set; }
    }
}
