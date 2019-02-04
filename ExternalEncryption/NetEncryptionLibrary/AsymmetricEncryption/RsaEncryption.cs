using ExternalEncryption.NetEncryptionLibrary.SymetricEncryption;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary.AsymmetricEncryption
{
  public class RsaEncryption : BaseEncryption
  {
    public RsaEncryption()
    {
      this.KeySize = 1024;
      this.DoOAEPPadding = false;
      this.MaxEncryptedBytes = (long) ((this.KeySize - 384) / 8 + 37);
    }

    public bool DoOAEPPadding { get; set; }

    public AsymmetricKeyPair CreateKeys()
    {
      AsymmetricKeyPair asymmetricKeyPair = new AsymmetricKeyPair();
      using (RSA.Create())
        ;
      return asymmetricKeyPair;
    }

    public override byte[] EncryptBytes(string publicKey, byte[] dataToEncrypt)
    {
      int num = (this.KeySize - 384) / 8 + 37;
      if (dataToEncrypt.Length > num)
        throw new CryptographicException(string.Format("RSA can encrypt a maximum of {0} bytes for a key size of {1}", (object) num, (object) this.KeySize));
      using (RSA rsa = RSA.Create())
        return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
    }

    public override byte[] DecryptBytes(string publicAndPrivateKey, byte[] dataToDecrypt)
    {
      using (RSA rsa = RSA.Create())
        return rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);
    }

    public override bool EncryptStream(string key, Stream inputStream, Stream outputStream, bool useBase64)
    {
      string str = Common.RandomString((int) this.MaxEncryptedBytes);
      byte[] bytes = this.EncodingMethod.GetBytes(this.EncryptString(key, str, true) + "|");
      outputStream.Write(bytes, 0, bytes.Length);
      return new SymmetricEncryption("~#!?@%.^fA79&|;Z", this.Salt, str)
      {
        CipherMethod = this.DefaultCipherMode,
        EncodingMethod = this.EncodingMethod,
        PaddingMode = this.Padding
      }.Encrypt(EncryptionProvider.Rijndael, inputStream, outputStream, useBase64);
    }

    public override bool DecryptStream(string key, Stream inputStream, Stream outputStream, bool useBase64)
    {
      List<byte> byteList = new List<byte>();
      for (byte index = (byte) inputStream.ReadByte(); index > (byte) 0 && index != (byte) 124; index = (byte) inputStream.ReadByte())
        byteList.Add(index);
      string inputString = this.EncodingMethod.GetString(byteList.ToArray());
      return new SymmetricEncryption("~#!?@%.^fA79&|;Z", this.Salt, this.DecryptString(key, inputString))
      {
        CipherMethod = this.DefaultCipherMode,
        EncodingMethod = this.EncodingMethod,
        PaddingMode = this.Padding
      }.Decrypt(EncryptionProvider.Rijndael, inputStream, outputStream, useBase64);
    }
  }
}
