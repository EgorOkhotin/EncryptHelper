using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class BlowfishCrypto : SymmetricAlgorithm
  {
    public BlowfishCrypto()
    {
      this.LegalKeySizesValue = new KeySizes[1]
      {
        new KeySizes(128, 256, 64)
      };
      this.LegalBlockSizesValue = new KeySizes[1]
      {
        new KeySizes(128, 128, 0)
      };
      this.BlockSize = 128;
      this.KeySize = 128;
      this.Padding = PaddingMode.Zeros;
      this.Mode = CipherMode.CBC;
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
    {
      if (rgbIV.Length != BlowfishTransform.BLOCK_SIZE)
        throw new CryptographicException("Specified initialization vector (IV) does not match the block size for this algorithm.");
      return (ICryptoTransform) new BlowfishTransform(false, rgbKey, rgbIV);
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
    {
      if (rgbIV.Length != BlowfishTransform.BLOCK_SIZE)
        throw new CryptographicException("Specified initialization vector (IV) does not match the block size for this algorithm.");
      return (ICryptoTransform) new BlowfishTransform(true, rgbKey, rgbIV);
    }

    public override void GenerateIV()
    {
      this.IV = new byte[16];
    }

    public override void GenerateKey()
    {
      this.Key = new byte[this.KeySize / 8];
      for (int lowerBound = this.Key.GetLowerBound(0); lowerBound < this.Key.GetUpperBound(0); ++lowerBound)
        this.Key[lowerBound] = (byte) 0;
    }
  }
}
