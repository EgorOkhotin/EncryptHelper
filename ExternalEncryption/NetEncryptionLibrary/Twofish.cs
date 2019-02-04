using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class Twofish : SymmetricAlgorithm
  {
    public Twofish()
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
      this.Mode = CipherMode.ECB;
    }

    public override ICryptoTransform CreateEncryptor(byte[] key, byte[] iv)
    {
      if (iv.Length != this.KeySize / 8)
        throw new CryptographicException("Specified initialization vector (IV) does not match the block size for this algorithm.");
      this.Key = key;
      if (this.Mode == CipherMode.CBC)
        this.IV = iv;
      return (ICryptoTransform) new TwofishEncryption(this.KeySize, ref this.KeyValue, ref this.IVValue, this.ModeValue, TwofishBase.EncryptionDirection.Encrypting);
    }

    public override ICryptoTransform CreateDecryptor(byte[] key, byte[] iv)
    {
      if (iv.Length != this.KeySize / 8)
        throw new CryptographicException("Specified initialization vector (IV) does not match the block size for this algorithm.");
      this.Key = key;
      if (this.Mode == CipherMode.CBC)
        this.IV = iv;
      return (ICryptoTransform) new TwofishEncryption(this.KeySize, ref this.KeyValue, ref this.IVValue, this.ModeValue, TwofishBase.EncryptionDirection.Decrypting);
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

    public override CipherMode Mode
    {
      set
      {
        if (value != CipherMode.CBC && value != CipherMode.ECB)
          throw new CryptographicException("Specified CipherMode is not supported.");
        this.ModeValue = value;
      }
    }
  }
}
