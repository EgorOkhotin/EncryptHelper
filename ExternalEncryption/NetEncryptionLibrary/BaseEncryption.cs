using ExternalEncryption.NetEncryptionLibrary.SymetricEncryption;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary
{
  public abstract class BaseEncryption : IEncryption
  {
    protected string Salt = "";
    protected CipherMode DefaultCipherMode = CipherMode.CBC;
    protected PaddingMode Padding = PaddingMode.PKCS7;
    protected const string InitializationVector = "~#!?@%.^fA79&|;Z";

    protected BaseEncryption()
    {
      this.EncodingMethod = Encoding.UTF8;
      this.MaxEncryptedBytes = long.MaxValue;
    }

    public int KeySize { get; set; }

    public long MaxEncryptedBytes { get; set; }

    public Encoding EncodingMethod { get; set; }

    public abstract byte[] EncryptBytes(string key, byte[] dataToEncrypt);

    public abstract byte[] DecryptBytes(string key, byte[] dataToDecrypt);

    public abstract bool EncryptStream(string key, Stream inputStream, Stream outputStream, bool useBase64);

    public abstract bool DecryptStream(string key, Stream inputStream, Stream outputStream, bool useBase64);

    public string EncodeBase64(byte[] input)
    {
      try
      {
        return Convert.ToBase64String(input);
      }
      catch
      {
        return string.Empty;
      }
    }

    public bool EncryptFile(string key, string inputFilePath, string outputFilePath, bool useBase64)
    {
      using (FileStream fileStream1 = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
      {
        using (FileStream fileStream2 = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
          return this.EncryptStream(key, (Stream) fileStream1, (Stream) fileStream2, useBase64);
      }
    }

    public bool DecryptFile(string key, string inputFilePath, string outputFilePath, bool useBase64)
    {
      using (FileStream fileStream1 = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
      {
        using (FileStream fileStream2 = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
          return this.DecryptStream(key, (Stream) fileStream1, (Stream) fileStream2, useBase64);
      }
    }

    public string EncryptString(string key, string inputString, bool writeEncryptionPrefix)
    {
      byte[] bytes1 = this.EncodingMethod.GetBytes(inputString);
      if ((long) bytes1.Length > this.MaxEncryptedBytes)
      {
        StringBuilder stringBuilder = new StringBuilder();
        string str = Common.RandomString((int) this.MaxEncryptedBytes);
        byte[] bytes2 = this.EncodingMethod.GetBytes(str);
        if (writeEncryptionPrefix)
          stringBuilder.Append("@KS@");
        stringBuilder.Append(this.EncodeBase64(this.EncryptBytes(key, bytes2)));
        stringBuilder.Append("|");
        stringBuilder.Append(this.EncodeBase64(new SymmetricEncryption("~#!?@%.^fA79&|;Z", this.Salt, str)
        {
          CipherMethod = this.DefaultCipherMode,
          EncodingMethod = this.EncodingMethod,
          PaddingMode = this.Padding
        }.Encrypt(EncryptionProvider.Rijndael, bytes1)));
        return stringBuilder.ToString();
      }
      if (writeEncryptionPrefix)
        return "@KS@" + this.EncodeBase64(this.EncryptBytes(key, bytes1));
      return this.EncodeBase64(this.EncryptBytes(key, bytes1));
    }

    public string DecryptString(string key, string inputString)
    {
      if (inputString.StartsWith("@KS@"))
        inputString = inputString.Substring(Common.PrefixLength);
      if (!inputString.Contains("|"))
        return this.EncodingMethod.GetString(this.DecryptBytes(key, Convert.FromBase64String(inputString)));
      byte[] dataToDecrypt = Convert.FromBase64String(inputString.Substring(0, inputString.IndexOf("|")));
      SymmetricEncryption symmetricEncryption = new SymmetricEncryption("~#!?@%.^fA79&|;Z", this.Salt, this.EncodingMethod.GetString(this.DecryptBytes(key, dataToDecrypt)));
      symmetricEncryption.CipherMethod = this.DefaultCipherMode;
      symmetricEncryption.EncodingMethod = this.EncodingMethod;
      symmetricEncryption.PaddingMode = this.Padding;
      byte[] input = Convert.FromBase64String(inputString.Substring(inputString.IndexOf("|") + 1));
      return this.EncodingMethod.GetString(symmetricEncryption.Decrypt(EncryptionProvider.Rijndael, input));
    }
  }
}
