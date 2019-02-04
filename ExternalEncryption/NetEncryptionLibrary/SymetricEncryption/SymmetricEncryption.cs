using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary.SymetricEncryption
{
  internal class SymmetricEncryption
  {
    private Encoding _encodingMethod = Encoding.UTF8;
    private CipherMode _cipherMode = CipherMode.CBC;
    private char[] ivChars = new char[16]
    {
      '~',
      '#',
      '!',
      '?',
      '@',
      '%',
      '.',
      '^',
      'f',
      'A',
      '7',
      '9',
      '&',
      '|',
      ';',
      'Z'
    };
    private PaddingMode? _paddingMode;
    private SymmetricAlgorithm alg;
    private EncryptionProvider provider;
    private string strKey;
    private string strSalt;

    public PaddingMode PaddingMode
    {
      get
      {
        if (!this._paddingMode.HasValue)
          return PaddingMode.PKCS7;
        return this._paddingMode.Value;
      }
      set
      {
        this._paddingMode = new PaddingMode?(value);
      }
    }

    public CipherMode CipherMethod
    {
      get
      {
        return this._cipherMode;
      }
      set
      {
        this._cipherMode = value;
      }
    }

    public Encoding EncodingMethod
    {
      get
      {
        return this._encodingMethod;
      }
      set
      {
        this._encodingMethod = value;
      }
    }

    public string Key
    {
      get
      {
        return this.strKey;
      }
      set
      {
        this.strKey = value;
      }
    }

    public string Salt
    {
      get
      {
        return this.strSalt;
      }
      set
      {
        this.strSalt = value;
      }
    }

    public SymmetricEncryption(string initializationVector, string salt, string key)
    {
      this.strKey = key;
      this.strSalt = salt;
      this.ivChars = this._encodingMethod.GetChars(this._encodingMethod.GetBytes(initializationVector.PadRight(16, '0')));
    }

    private byte[] GetIV()
    {
      byte[] bytes;
      switch (this.provider)
      {
        case EncryptionProvider.Rijndael:
          bytes = this._encodingMethod.GetBytes(this.ivChars, 0, this.alg.BlockSize / 8);
          break;
        case EncryptionProvider.Twofish:
          bytes = Encoding.ASCII.GetBytes(this.ivChars, 0, this.alg.BlockSize / 8);
          break;
        default:
          bytes = this._encodingMethod.GetBytes(this.ivChars, 0, this.alg.BlockSize / 8);
          break;
      }
      return bytes;
    }

    private byte[] GetKey()
    {
      if (this.alg.LegalKeySizes.Length != 0)
      {
        int num1 = this.strKey.Length * 8;
        int minSize = this.alg.LegalKeySizes[0].MinSize;
        int maxSize = this.alg.LegalKeySizes[0].MaxSize;
        int skipSize = this.alg.LegalKeySizes[0].SkipSize;
        if (num1 > maxSize)
          this.strKey = this.strKey.Substring(0, maxSize / 8);
        else if (num1 < maxSize)
        {
          int num2 = num1 <= minSize ? minSize : num1 - num1 % skipSize + skipSize;
          if (num1 < num2)
            this.strKey = this.strKey.PadRight(num2 / 8, '*');
        }
      }
      Rfc2898DeriveBytes rfc2898DeriveBytes;
      if (this.provider == EncryptionProvider.Twofish)
      {
        if (this.strKey.Length > this.alg.LegalKeySizes[0].MinSize / 8)
          this.strKey = this.strKey.Substring(0, this.alg.LegalKeySizes[0].MinSize / 8);
        rfc2898DeriveBytes = new Rfc2898DeriveBytes(this.strKey, Encoding.ASCII.GetBytes(this.strSalt));
      }
      else
        rfc2898DeriveBytes = new Rfc2898DeriveBytes(this.strKey, this._encodingMethod.GetBytes(this.strSalt));
      return rfc2898DeriveBytes.GetBytes(this.strKey.Length);
    }

    private void InitializeAlgorithm(EncryptionProvider encryptionType)
    {
      switch (encryptionType)
      {
        case EncryptionProvider.Rijndael:
          this.alg = (SymmetricAlgorithm) Aes.Create();
          this.provider = EncryptionProvider.Rijndael;
          this.alg.Padding = this.PaddingMode;
          this.alg.Mode = this._cipherMode;
          break;
        case EncryptionProvider.TripleDES:
          this.alg = (SymmetricAlgorithm) TripleDES.Create();
          this.provider = EncryptionProvider.TripleDES;
          this.alg.Padding = this.PaddingMode;
          this.alg.Mode = this._cipherMode;
          break;
        case EncryptionProvider.Blowfish:
          this.alg = (SymmetricAlgorithm) new BlowfishCrypto();
          this.provider = EncryptionProvider.Blowfish;
          this.alg.Padding = this.PaddingMode;
          this.alg.Mode = this._cipherMode;
          break;
        case EncryptionProvider.Twofish:
          this.alg = (SymmetricAlgorithm) new Twofish();
          this.provider = EncryptionProvider.Twofish;
          this.alg.Padding = PaddingMode.Zeros;
          this.alg.Mode = CipherMode.CBC;
          break;
      }
      this.alg.Key = this.GetKey();
      this.alg.IV = this.GetIV();
    }

    public int GetKeySize(EncryptionProvider encryptionType)
    {
      this.InitializeAlgorithm(encryptionType);
      return this.alg.KeySize;
    }

    public byte[] Encrypt(EncryptionProvider encryptionType, byte[] input)
    {
      if (input == null)
        throw new Exception("Invalid Input Provided - Unable to Encrypt.");
      this.InitializeAlgorithm(encryptionType);
      using (MemoryStream memoryStream = new MemoryStream())
      {
        using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, this.alg.CreateEncryptor(), CryptoStreamMode.Write))
        {
          cryptoStream.Write(input, 0, input.Length);
          cryptoStream.FlushFinalBlock();
          return memoryStream.ToArray();
        }
      }
    }

    public MemoryStream Encrypt(EncryptionProvider encryptionType, MemoryStream memStream)
    {
      byte[] array = memStream.ToArray();
      return new MemoryStream(this.Encrypt(encryptionType, array));
    }

    public bool Encrypt(EncryptionProvider encryptionType, Stream inputStream, Stream outputStream, bool useBase64)
    {
      this.InitializeAlgorithm(encryptionType);
      try
      {
        outputStream.Write(Common.PrefixBytes, 0, Common.PrefixLength);
        ICryptoTransform encryptor = this.alg.CreateEncryptor();
        CryptoStream cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write);
        int count1 = 4096;
        byte[] buffer = new byte[count1];
        int count2;
        while ((count2 = inputStream.Read(buffer, 0, count1)) > 0)
          cryptoStream.Write(buffer, 0, count2);
        cryptoStream.FlushFinalBlock();
      }
      catch (Exception ex)
      {
        return false;
      }
      return true;
    }

    public bool Encrypt(EncryptionProvider encryptionType, string inputFile, string outputFile, bool useBase64)
    {
      if (!File.Exists(inputFile))
        return false;
      try
      {
        using (FileStream fileStream1 = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        {
          using (FileStream fileStream2 = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            return this.Encrypt(encryptionType, (Stream) fileStream1, (Stream) fileStream2, useBase64);
        }
      }
      catch
      {
        return false;
      }
    }

    public byte[] Decrypt(EncryptionProvider encryptionType, byte[] input)
    {
      if (input == null)
        throw new Exception("Bad Input Provided - Unable to Decrypt.");
      this.InitializeAlgorithm(encryptionType);
      using (MemoryStream memoryStream = new MemoryStream())
      {
        using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, this.alg.CreateDecryptor(), CryptoStreamMode.Write))
        {
          cryptoStream.Write(input, 0, input.Length);
          cryptoStream.FlushFinalBlock();
        }
        return memoryStream.ToArray();
      }
    }

    public MemoryStream Decrypt(EncryptionProvider encryptionType, MemoryStream memStream)
    {
      try
      {
        byte[] array = memStream.ToArray();
        return new MemoryStream(this.Decrypt(encryptionType, array));
      }
      catch
      {
        return (MemoryStream) null;
      }
    }

    public bool Decrypt(EncryptionProvider encryptionType, Stream inputStream, Stream outputStream, bool useBase64)
    {
      this.InitializeAlgorithm(encryptionType);
      try
      {
        ICryptoTransform decryptor = this.alg.CreateDecryptor();
        CryptoStream cryptoStream = new CryptoStream(outputStream, decryptor, CryptoStreamMode.Write);
        int count1 = 4096;
        byte[] numArray1 = new byte[count1];
        byte[] numArray2 = new byte[count1];
        bool flag = true;
        int num;
        while ((num = inputStream.Read(numArray1, 0, count1)) > 0)
        {
          byte[] dest = new byte[count1];
          numArray1.CopyTo((Array) dest, 0);
          int count2 = num;
          if (flag)
          {
            flag = false;
            if (Common.PrefixMatch(numArray1))
            {
              dest = new byte[count1];
              Common.CopyByteArray(numArray1, ref dest, Common.PrefixLength, 0);
              count2 = num - Common.PrefixLength;
            }
          }
          cryptoStream.Write(dest, 0, count2);
        }
        cryptoStream.FlushFinalBlock();
      }
      catch (Exception ex)
      {
        return false;
      }
      return true;
    }

    public bool Decrypt(EncryptionProvider encryptionType, string inputFile, string outputFile, bool useBase64)
    {
      if (!File.Exists(inputFile))
        return false;
      try
      {
        using (FileStream fileStream1 = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        {
          using (FileStream fileStream2 = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            return this.Decrypt(encryptionType, (Stream) fileStream1, (Stream) fileStream2, useBase64);
        }
      }
      catch
      {
        return false;
      }
    }
  }
}
