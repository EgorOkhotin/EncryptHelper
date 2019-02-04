using ExternalEncryption.NetEncryptionLibrary;
using ExternalEncryption.NetEncryptionLibrary.AsymmetricEncryption;
using ExternalEncryption.NetEncryptionLibrary.SymetricEncryption;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace KellermanSoftware.NetEncryptionLibrary
{
  public class Encryption
  {
    private string _salt = "";
    private string _initializationVector = "~#!?@%.^fA79&|;Z";
    private Encoding _encodingMethod = Encoding.UTF8;
    private CipherMode _cipherMode = CipherMode.CBC;
    private PaddingMode _padding = PaddingMode.PKCS7;
    private Random r = new Random();
    private QuotedPrintable _oQuoted;

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

    public PaddingMode Padding
    {
      get
      {
        return this._padding;
      }
      set
      {
        this._padding = value;
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

    public string Salt
    {
      get
      {
        return this._salt;
      }
      set
      {
        this._salt = value;
      }
    }

    public string InitializationVector
    {
      get
      {
        return this._initializationVector;
      }
      set
      {
        this._initializationVector = value.PadRight(16, '0');
      }
    }

    public bool WriteEncryptionPrefix { get; set; }

    public Encryption(string trialExtensionCode)
    {
      string productCode = "CRYPT-V" + Encryption.AssemblyMajorVersion;
      string str1 = "Kellerman Encryption Library";
      string str2 = "www.KellermanSoftware.com";
      string productName = str1;
      string website = str2;
      string empty1 = string.Empty;
      string empty2 = string.Empty;
      //LicensingLibrary licensingLibrary = new LicensingLibrary(productCode, productName, website, empty1, empty2);
      //if (!licensingLibrary.ExtendTrial(trialExtensionCode))
      //  throw new Exception(licensingLibrary.AdditionalInfo);
      //if (!licensingLibrary.CheckLicense())
      //  throw new Exception(licensingLibrary.AdditionalInfo);
      this.Initialize();
    }

    public Encryption(string userName, string licenseKey)
    {
      this.CheckLicense(userName, licenseKey);
      this.Initialize();
    }

    public Encryption()
    {
      this.CheckLicense(string.Empty, string.Empty);
      this.Initialize();
    }

    private bool CheckLicense(string userName, string licenseKey)
    {
      //string productCode = "CRYPT-V" + Encryption.AssemblyMajorVersion;
      //string str1 = "Kellerman Encryption Library";
      //string str2 = "www.KellermanSoftware.com";
      //string productName = str1;
      //string website = str2;
      //string userName1 = userName;
      //string license = licenseKey;
      ////LicensingLibrary licensingLibrary = new LicensingLibrary(productCode, productName, website, userName1, license);
      ////if (!licensingLibrary.CheckLicense())
      ////  throw new Exception(licensingLibrary.AdditionalInfo);
      return true;
    }

    private void Initialize()
    {
      this.WriteEncryptionPrefix = true;
    }

    public byte[] HexadecimalStringToByteArray(string hexString)
    {
      int length = hexString.Length;
      byte[] numArray = new byte[length / 2];
      int startIndex = 0;
      while (startIndex < length)
      {
        numArray[startIndex / 2] = Convert.ToByte(hexString.Substring(startIndex, 2), 16);
        startIndex += 2;
      }
      return numArray;
    }

    public string BytesToQuotedPrintable(byte[] bytes)
    {
      try
      {
        if (this._oQuoted == null)
          this._oQuoted = new QuotedPrintable();
        return this._oQuoted.Encode(bytes, this._encodingMethod);
      }
      catch
      {
        return string.Empty;
      }
    }

    public string BytesToHexString(byte[] bytes)
    {
      try
      {
        char[] chArray1 = new char[16]
        {
          '0',
          '1',
          '2',
          '3',
          '4',
          '5',
          '6',
          '7',
          '8',
          '9',
          'A',
          'B',
          'C',
          'D',
          'E',
          'F'
        };
        char[] chArray2 = new char[bytes.Length * 2];
        for (int index = 0; index < bytes.Length; ++index)
        {
          int num = (int) bytes[index];
          chArray2[index * 2] = chArray1[num >> 4];
          chArray2[index * 2 + 1] = chArray1[num & 15];
        }
        return new string(chArray2);
      }
      catch
      {
        return string.Empty;
      }
    }

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

    public byte[] DecodeBase64(string input)
    {
      try
      {
        return Convert.FromBase64String(input);
      }
      catch
      {
        return (byte[]) null;
      }
    }

    public string uuEncode(string input)
    {
      try
      {
        string str1 = string.Empty;
        if (input.Length % 3 != 0)
        {
          string str2 = new string(' ', 3 - input.Length % 3);
          input += str2;
        }
        int length = input.Length;
        int startIndex = 1;
        while (startIndex <= length)
        {
          str1 = str1 + Convert.ToString((char) ((int) Convert.ToChar(input.Substring(startIndex - 1, 1)) / 4 + 32)) + Convert.ToString((char) ((int) Convert.ToChar(input.Substring(startIndex - 1, 1)) % 4 * 16 + (int) Convert.ToChar(input.Substring(startIndex, 1)) / 16 + 32)) + Convert.ToString((char) ((int) Convert.ToChar(input.Substring(startIndex, 1)) % 16 * 4 + (int) Convert.ToChar(input.Substring(startIndex + 1, 1)) / 64 + 32)) + Convert.ToString((char) ((int) Convert.ToChar(input.Substring(startIndex + 1, 1)) % 64 + 32));
          startIndex += 3;
        }
        return str1;
      }
      catch
      {
        return string.Empty;
      }
    }

    public string uuDecode(string input)
    {
      try
      {
        string str = string.Empty;
        int length = input.Length;
        int startIndex = 1;
        while (startIndex <= length)
        {
          str = str + Convert.ToString((char) (((int) Convert.ToChar(input.Substring(startIndex - 1, 1)) - 32) * 4 + ((int) Convert.ToChar(input.Substring(startIndex, 1)) - 32) / 16)) + Convert.ToString((char) ((int) Convert.ToChar(input.Substring(startIndex, 1)) % 16 * 16 + ((int) Convert.ToChar(input.Substring(startIndex + 1, 1)) - 32) / 4)) + Convert.ToString((char) ((int) Convert.ToChar(input.Substring(startIndex + 1, 1)) % 4 * 64 + (int) Convert.ToChar(input.Substring(startIndex + 2, 1)) - 32));
          startIndex += 4;
        }
        return str;
      }
      catch
      {
        return string.Empty;
      }
    }

    [Obsolete("Use HashStringBase64 instead. There is also a new method HashStringHex", false)]
    public string HashString(HashProvider hashType, string input)
    {
      return this.HashStringBase64(hashType, input);
    }

    public string HashStringBase64(HashProvider hashType, string input)
    {
      try
      {
        Hashing hashing = new Hashing();
        hashing.EncodingMethod = this._encodingMethod;
        byte[] bytes = this._encodingMethod.GetBytes(input);
        return this.EncodeBase64(this._salt.Length <= 0 ? hashing.ComputeHash(hashType, bytes) : hashing.ComputeHashSalt(hashType, bytes, this._salt));
      }
      catch
      {
        return string.Empty;
      }
    }

    public string HashStringHex(HashProvider hashType, string input)
    {
      string input1 = this.HashString(hashType, input);
      if (string.IsNullOrEmpty(input1))
        return input1;
      return BitConverter.ToString(this.DecodeBase64(input1)).Replace("-", string.Empty);
    }

    [Obsolete("Use HashStringBase64 instead. There is also a new method HashStringHex", false)]
    public string HashString(HashProvider hashType, string input, string key)
    {
      return this.HashStringBase64(hashType, input, key);
    }

    public string HashStringBase64(HashProvider hashType, string input, string key)
    {
      try
      {
        Hashing hashing = new Hashing();
        hashing.EncodingMethod = this._encodingMethod;
        byte[] bytes1 = this._encodingMethod.GetBytes(input);
        byte[] bytes2 = this._encodingMethod.GetBytes(key);
        return this.EncodeBase64(this._salt.Length <= 0 ? hashing.ComputeHash(hashType, bytes1, bytes2) : hashing.ComputeHashSalt(hashType, bytes1, bytes2, this._salt));
      }
      catch
      {
        return string.Empty;
      }
    }

    public string HashStringHex(HashProvider hashType, string input, string key)
    {
      string input1 = this.HashStringBase64(hashType, input, key);
      if (string.IsNullOrEmpty(input1))
        return input1;
      return BitConverter.ToString(this.DecodeBase64(input1)).Replace("-", string.Empty);
    }

    [Obsolete("Use HashBytesBase64 instead. There is also a new method HashBytesHex", false)]
    public string HashBytes(HashProvider hashType, byte[] input)
    {
      return this.HashBytesBase64(hashType, input);
    }

    public string HashBytesBase64(HashProvider hashType, byte[] input)
    {
      try
      {
        Hashing hashing = new Hashing();
        hashing.EncodingMethod = this._encodingMethod;
        if (this._salt.Length > 0)
          return this.EncodeBase64(hashing.ComputeHashSalt(hashType, input, this._salt));
        return this.EncodeBase64(hashing.ComputeHash(hashType, input));
      }
      catch
      {
        return string.Empty;
      }
    }

    public string HashBytesHex(HashProvider hashType, byte[] input)
    {
      string input1 = this.HashBytes(hashType, input);
      if (string.IsNullOrEmpty(input1))
        return input1;
      return BitConverter.ToString(this.DecodeBase64(input1)).Replace("-", string.Empty);
    }

    [Obsolete("Deprecated.  Use HashBytesBase64 instead. There is also a new method HashBytesHex", false)]
    public string HashBytes(HashProvider hashType, byte[] input, byte[] key)
    {
      return this.HashBytesBase64(hashType, input, key);
    }

    public string HashBytesBase64(HashProvider hashType, byte[] input, byte[] key)
    {
      try
      {
        Hashing hashing = new Hashing();
        hashing.EncodingMethod = this._encodingMethod;
        if (this._salt.Length > 0)
          return this.EncodeBase64(hashing.ComputeHashSalt(hashType, input, key, this._salt));
        return this.EncodeBase64(hashing.ComputeHash(hashType, input, key));
      }
      catch
      {
        return string.Empty;
      }
    }

    public string HashBytesHex(HashProvider hashType, byte[] input, byte[] key)
    {
      string input1 = this.HashBytesBase64(hashType, input, key);
      if (string.IsNullOrEmpty(input1))
        return input1;
      return BitConverter.ToString(this.DecodeBase64(input1)).Replace("-", string.Empty);
    }

    [Obsolete("Deprecated. Use HashFileBase64 instead. There is also a new method HashFileHex", false)]
    public string HashFile(HashProvider hashType, string inputFilePath)
    {
      return this.HashFileBase64(hashType, inputFilePath);
    }

    public string HashFileBase64(HashProvider hashType, string inputFilePath)
    {
      try
      {
        Hashing hashing = new Hashing();
        hashing.EncodingMethod = this._encodingMethod;
        if (this._salt.Length > 0)
          return Convert.ToBase64String(hashing.ComputeHash(hashType, inputFilePath, this._salt));
        return Convert.ToBase64String(hashing.ComputeHash(hashType, inputFilePath));
      }
      catch
      {
        return string.Empty;
      }
    }

    public string HashFileHex(HashProvider hashType, string inputFilePath)
    {
      string input = this.HashFileBase64(hashType, inputFilePath);
      if (string.IsNullOrEmpty(input))
        return input;
      return BitConverter.ToString(this.DecodeBase64(input)).Replace("-", string.Empty);
    }

    [Obsolete("Deprecated. Use HashFileBase64 instead. There is also a new method HashFileHex", false)]
    public string HashFile(HashProvider hashType, string inputFilePath, string key)
    {
      return this.HashFileBase64(hashType, inputFilePath, key);
    }

    public string HashFileBase64(HashProvider hashType, string inputFilePath, string key)
    {
      try
      {
        Hashing hashing = new Hashing();
        hashing.EncodingMethod = this._encodingMethod;
        byte[] bytes = this._encodingMethod.GetBytes(key);
        if (this._salt.Length > 0)
          return Convert.ToBase64String(hashing.ComputeHash(hashType, inputFilePath, bytes, this._salt));
        return Convert.ToBase64String(hashing.ComputeHash(hashType, inputFilePath, bytes));
      }
      catch
      {
        return string.Empty;
      }
    }

    public string HashFileHex(HashProvider hashType, string inputFilePath, string key)
    {
      string input = this.HashFileBase64(hashType, inputFilePath, key);
      if (string.IsNullOrEmpty(input))
        return input;
      return BitConverter.ToString(this.DecodeBase64(input)).Replace("-", string.Empty);
    }

    public AsymmetricKeyPair GenerateRSAKeys()
    {
      return new RsaEncryption().CreateKeys();
    }

    public int GetSymmetricEncryptionKeySize(EncryptionProvider encryptionType)
    {
      return new SymmetricEncryption(string.Empty, string.Empty, string.Empty).GetKeySize(encryptionType);
    }

    public string EncryptString(EncryptionProvider encryptionType, string key, string input)
    {
      if (encryptionType == EncryptionProvider.RSA)
      {
        IEncryption encryption = EncryptionFactory.CreateEncryption(encryptionType);
        try
        {
          encryption.EncodingMethod = this.EncodingMethod;
          return encryption.EncryptString(key, input, this.WriteEncryptionPrefix);
        }
        catch (Exception ex)
        {
          return ex.Message;
        }
      }
      else
      {
        try
        {
          SymmetricEncryption symmetricEncryption = new SymmetricEncryption(this._initializationVector, this._salt, key);
          symmetricEncryption.CipherMethod = this.CipherMethod;
          symmetricEncryption.EncodingMethod = this.EncodingMethod;
          symmetricEncryption.PaddingMode = this.Padding;
          byte[] bytes = this._encodingMethod.GetBytes(input);
          if (this.WriteEncryptionPrefix)
            return "@KS@" + this.EncodeBase64(symmetricEncryption.Encrypt(encryptionType, bytes));
          return this.EncodeBase64(symmetricEncryption.Encrypt(encryptionType, bytes));
        }
        catch (Exception ex)
        {
          return ex.Message;
        }
      }
    }

    public byte[] EncryptBytes(EncryptionProvider encryptionType, string key, byte[] input)
    {
      if (encryptionType == EncryptionProvider.RSA)
      {
        IEncryption encryption = EncryptionFactory.CreateEncryption(encryptionType);
        encryption.EncodingMethod = this.EncodingMethod;
        return encryption.EncryptBytes(key, input);
      }
      try
      {
        return new SymmetricEncryption(this._initializationVector, this._salt, key)
        {
          CipherMethod = this.CipherMethod,
          EncodingMethod = this.EncodingMethod,
          PaddingMode = this.Padding
        }.Encrypt(encryptionType, input);
      }
      catch
      {
        return (byte[]) null;
      }
    }

    public MemoryStream EncryptMemoryStream(EncryptionProvider encryptionType, string key, MemoryStream stream)
    {
      try
      {
        return new SymmetricEncryption(this._initializationVector, this._salt, key)
        {
          CipherMethod = this.CipherMethod,
          EncodingMethod = this.EncodingMethod,
          PaddingMode = this.Padding
        }.Encrypt(encryptionType, stream);
      }
      catch
      {
        return (MemoryStream) null;
      }
    }

    public bool EncryptStream(EncryptionProvider encryptionType, string key, Stream inputStream, Stream outputStream, bool useBase64)
    {
      if (encryptionType == EncryptionProvider.RSA)
      {
        IEncryption encryption = EncryptionFactory.CreateEncryption(encryptionType);
        try
        {
          encryption.EncodingMethod = this.EncodingMethod;
          return encryption.EncryptStream(key, inputStream, outputStream, useBase64);
        }
        catch (Exception ex)
        {
          return false;
        }
      }
      else
      {
        try
        {
          return new SymmetricEncryption(this._initializationVector, this._salt, key)
          {
            CipherMethod = this.CipherMethod,
            EncodingMethod = this.EncodingMethod,
            PaddingMode = this.Padding
          }.Encrypt(encryptionType, inputStream, outputStream, useBase64);
        }
        catch
        {
          return false;
        }
      }
    }

    public bool EncryptFile(EncryptionProvider encryptionType, string key, string inputFilePath, string outputFilePath, bool useBase64)
    {
      if (encryptionType == EncryptionProvider.RSA)
      {
        IEncryption encryption = EncryptionFactory.CreateEncryption(encryptionType);
        try
        {
          encryption.EncodingMethod = this.EncodingMethod;
          return encryption.EncryptFile(key, inputFilePath, outputFilePath, useBase64);
        }
        catch (Exception ex)
        {
          return false;
        }
      }
      else
      {
        try
        {
          return new SymmetricEncryption(this._initializationVector, this._salt, key)
          {
            CipherMethod = this.CipherMethod,
            EncodingMethod = this.EncodingMethod,
            PaddingMode = this.Padding
          }.Encrypt(encryptionType, inputFilePath, outputFilePath, useBase64);
        }
        catch
        {
          return false;
        }
      }
    }

    public bool EncryptFile(EncryptionProvider encryptionType, string key, string inputFilePath, string outputFilePath)
    {
      return this.EncryptFile(encryptionType, key, inputFilePath, outputFilePath, true);
    }

    public string DecryptString(EncryptionProvider encryptionType, string key, string input)
    {
      if (encryptionType == EncryptionProvider.RSA)
      {
        IEncryption encryption = EncryptionFactory.CreateEncryption(encryptionType);
        try
        {
          return encryption.DecryptString(key, input);
        }
        catch (Exception ex)
        {
          return string.Empty;
        }
      }
      else
      {
        try
        {
          if (input.StartsWith("@KS@"))
            input = input.Substring(Common.PrefixLength);
          return this._encodingMethod.GetString(new SymmetricEncryption(this._initializationVector, this._salt, key)
          {
            CipherMethod = this.CipherMethod,
            EncodingMethod = this.EncodingMethod,
            PaddingMode = this.Padding
          }.Decrypt(encryptionType, Convert.FromBase64String(input)));
        }
        catch
        {
          return string.Empty;
        }
      }
    }

    public byte[] DecryptBytes(EncryptionProvider encryptionType, string key, byte[] input)
    {
      if (encryptionType == EncryptionProvider.RSA)
        return EncryptionFactory.CreateEncryption(encryptionType).DecryptBytes(key, input);
      try
      {
        return new SymmetricEncryption(this._initializationVector, this._salt, key)
        {
          CipherMethod = this.CipherMethod,
          EncodingMethod = this.EncodingMethod,
          PaddingMode = this.Padding
        }.Decrypt(encryptionType, input);
      }
      catch
      {
        return (byte[]) null;
      }
    }

    public MemoryStream DecryptMemoryStream(EncryptionProvider encryptionType, string key, MemoryStream stream)
    {
      try
      {
        return new SymmetricEncryption(this._initializationVector, this._salt, key)
        {
          CipherMethod = this.CipherMethod,
          EncodingMethod = this.EncodingMethod,
          PaddingMode = this.Padding
        }.Decrypt(encryptionType, stream);
      }
      catch
      {
        return (MemoryStream) null;
      }
    }

    public bool DecryptStream(EncryptionProvider encryptionType, string key, Stream inputStream, Stream outputStream, bool useBase64)
    {
      if (encryptionType == EncryptionProvider.RSA)
      {
        IEncryption encryption = EncryptionFactory.CreateEncryption(encryptionType);
        try
        {
          encryption.EncodingMethod = this.EncodingMethod;
          return encryption.DecryptStream(key, inputStream, outputStream, useBase64);
        }
        catch (Exception ex)
        {
          return false;
        }
      }
      else
      {
        try
        {
          return new SymmetricEncryption(this._initializationVector, this._salt, key)
          {
            CipherMethod = this.CipherMethod,
            EncodingMethod = this.EncodingMethod,
            PaddingMode = this.Padding
          }.Decrypt(encryptionType, inputStream, outputStream, useBase64);
        }
        catch
        {
          return false;
        }
      }
    }

    public bool DecryptFile(EncryptionProvider encryptionType, string key, string inputFilePath, string outputFilePath, bool useBase64)
    {
      if (encryptionType == EncryptionProvider.RSA)
      {
        IEncryption encryption = EncryptionFactory.CreateEncryption(encryptionType);
        try
        {
          encryption.EncodingMethod = this.EncodingMethod;
          return encryption.DecryptFile(key, inputFilePath, outputFilePath, useBase64);
        }
        catch (Exception ex)
        {
          return false;
        }
      }
      else
      {
        try
        {
          return new SymmetricEncryption(this._initializationVector, this._salt, key)
          {
            CipherMethod = this.CipherMethod,
            EncodingMethod = this.EncodingMethod,
            PaddingMode = this.Padding
          }.Decrypt(encryptionType, inputFilePath, outputFilePath, useBase64);
        }
        catch
        {
          return false;
        }
      }
    }

    public bool DecryptFile(EncryptionProvider encryptionType, string key, string inputFilePath, string outputFilePath)
    {
      return this.DecryptFile(encryptionType, key, inputFilePath, outputFilePath, true);
    }

    private bool AreBytesBase64(byte[] bytes, int maxLength)
    {
      byte[] bytes1 = Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=");
      for (int index1 = 0; index1 < maxLength; ++index1)
      {
        bool flag = false;
        for (int index2 = 0; index2 < bytes1.Length; ++index2)
        {
          if ((int) bytes[index1] == (int) bytes1[index2])
          {
            flag = true;
            break;
          }
        }
        if (!flag)
          return false;
      }
      return true;
    }

    public bool IsStringEncrypted(string value, bool strict)
    {
      Regex regex = new Regex("^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\+\\/]+[=]{0,3}$");
      if (strict)
        return value.StartsWith("@KS@");
      if (string.IsNullOrEmpty(value) || value.Length < 10 || value.Length % 4 != 0)
        return false;
      if (value.StartsWith("@KS@"))
        return true;
      if (!regex.Match(value).Success || Regex.IsMatch(value, "^4[\\d]{15}$") || Regex.IsMatch(value, "^5[\\d]{15}$"))
        return false;
      if (Regex.IsMatch(value, "^6011[\\d]{12}$"))
        return false;
      try
      {
        Convert.FromBase64String(value);
        return true;
      }
      catch
      {
        return false;
      }
    }

    public string GenerateSixDigitPin(string value)
    {
      string str = this.GetStringCRC32(value).ToString();
      if (str.Length > 6)
        return str.Substring(0, 6);
      return str.PadRight(6, '0');
    }

    public long GetStringAdler32(string value)
    {
      return (long) new Adler32().GetStringAdler32(value);
    }

    public long GetStreamAdler32(Stream value)
    {
      return (long) new Adler32().GetStreamAdler32(value);
    }

    public string GetStreamAdler32Hex(Stream value)
    {
      return string.Format("{0:X}", (object) this.GetStreamAdler32(value));
    }

    public long GetFileAdler32(string filePath)
    {
      return (long) new Adler32().GetFileAdler32(filePath);
    }

    public string GetFileAdler32Hex(string filePath)
    {
      return string.Format("{0:X}", (object) this.GetFileCRC32(filePath));
    }

    public long GetStringCRC32(string value)
    {
      return (long) new CRC32().GetStringCRC32(value);
    }

    public long GetStreamCRC32(Stream stream)
    {
      return (long) new CRC32().GetStreamCRC32(stream);
    }

    public long GetFileCRC32(string filePath)
    {
      return (long) new CRC32().GetFileCRC32(filePath);
    }

    public string GetFileCRC32Hex(string filePath)
    {
      return string.Format("{0:X}", (object) this.GetFileCRC32(filePath));
    }

    public string GenerateKey()
    {
      byte[] numArray = new byte[16];
      RandomNumberGenerator.Create().GetBytes(numArray);
      return this._encodingMethod.GetString(numArray);
    }

    private byte[] Random256()
    {
      return Encoding.ASCII.GetBytes(this.GetRandomString(256));
    }

    public void SecureDirectoryErase(string directoryPath)
    {
      this.SecureDirectoryErase(directoryPath, "*.*", SearchOption.AllDirectories);
    }

    public void SecureDirectoryErase(string directoryPath, string searchPattern)
    {
      this.SecureDirectoryErase(directoryPath, searchPattern, SearchOption.AllDirectories);
    }

    public void SecureDirectoryErase(string directoryPath, string searchPattern, SearchOption searchOption)
    {
      if (!Directory.Exists(directoryPath))
        return;
      foreach (string file in Directory.GetFiles(directoryPath, searchPattern, searchOption))
        this.SecureFileErase(file);
      foreach (string directory in Directory.GetDirectories(directoryPath, searchPattern, searchOption))
        this.SecureDirectoryErase(directory, searchPattern, searchOption);
      if (Directory.GetFiles(directoryPath).Length != 0 || Directory.GetDirectories(directoryPath).Length != 0)
        return;
      string str = Path.Combine(Path.GetDirectoryName(directoryPath), "ZSECURE");
      Directory.Move(directoryPath, str);
      Directory.Delete(str, false);
    }

    private byte[] GetRandomBytes(int length)
    {
      StringBuilder stringBuilder = new StringBuilder(length);
      for (int index = 0; index < length; ++index)
        stringBuilder.Append(this.RandomChar(36));
      return Encoding.ASCII.GetBytes(stringBuilder.ToString());
    }

    public void SecureFileErase(string filePath)
    {
      int bufferSize = 1048576;
      if (!File.Exists(filePath))
        return;
      using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None, bufferSize))
      {
        int length = (int) fileStream.Length;
        fileStream.Seek(0L, SeekOrigin.Begin);
        int num1 = 0;
        byte[] buffer = (byte[]) null;
        int num2 = 0;
        byte[] randomBytes = this.GetRandomBytes(256);
        while ((long) num1 < fileStream.Length)
        {
          int count = bufferSize;
          int num3 = length - num1;
          if (count > num3)
          {
            count = num3;
            if (buffer == null)
            {
              buffer = new byte[count];
              for (int index = 0; index < count; ++index)
              {
                buffer[index] = randomBytes[num2++];
                if (num2 >= (int) byte.MaxValue)
                  num2 = 0;
              }
            }
          }
          else if (buffer == null)
          {
            buffer = new byte[bufferSize];
            for (int index = 0; index < bufferSize; ++index)
            {
              buffer[index] = randomBytes[num2++];
              if (num2 >= (int) byte.MaxValue)
                num2 = 0;
            }
          }
          fileStream.Write(buffer, 0, count);
          num1 += count;
        }
      }
      string str = Path.Combine(Path.GetDirectoryName(filePath), "ZSECURE.ZPM");
      File.Move(filePath, str);
      File.Delete(str);
    }

    public byte[] CompressBytes(CompressionType compressionType, byte[] input)
    {
      return new Compression().CompressBytes(compressionType, input);
    }

    public byte[] DecompressBytes(CompressionType compressionType, byte[] input)
    {
      return new Compression().DecompressBytes(compressionType, input);
    }

    public Stream CompressStream(CompressionType compressionType, Stream input)
    {
      return new Compression().CompressStream(compressionType, input);
    }

    public Stream DecompressStream(CompressionType compressionType, Stream input)
    {
      return new Compression().DecompressStream(compressionType, input);
    }

    public void CompressFile(CompressionType compressionType, string inputFilePath, string outputFilePath)
    {
      new Compression().CompressFile(compressionType, inputFilePath, outputFilePath);
    }

    public void DecompressFile(CompressionType compressionType, string inputFilePath, string outputFilePath)
    {
      new Compression().DecompressFile(compressionType, inputFilePath, outputFilePath);
    }

    private string GetRandomString(int iLength)
    {
      StringBuilder stringBuilder = new StringBuilder(iLength);
      for (int index = 0; index < iLength; ++index)
        stringBuilder.Append(this.RandomChar(36));
      return stringBuilder.ToString();
    }

    private string RandomChar(int iBase)
    {
      int num;
      switch (iBase)
      {
        case 10:
          num = this.r.Next(0, 9);
          break;
        case 16:
          num = this.r.Next(0, 15);
          break;
        case 36:
          num = this.r.Next(0, 35);
          break;
        default:
          num = this.r.Next(0, 35);
          break;
      }
      return num < 0 || num > 9 ? Encryption.Chr(num + 55) : num.ToString();
    }

    private static string Chr(int iASCIICode)
    {
      return Encoding.ASCII.GetString(new byte[1]
      {
        (byte) iASCIICode
      }).Substring(0, 1);
    }

    public bool CrcEqual(string file1, string file2)
    {
      return this.GetFileCRC32(file1) == this.GetFileCRC32(file2);
    }

    private static string AssemblyMajorVersion
    {
      get
      {
        return typeof (Encryption).GetTypeInfo().Assembly.GetName().Version.Major.ToString();
      }
    }
  }
}
