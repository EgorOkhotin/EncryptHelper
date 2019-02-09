using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class Hashing
  {
    private Encoding _encodingMethod = Encoding.UTF8;

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

    private HashAlgorithm GetHashAlgorithm(HashProvider hashType)
    {
      switch (hashType)
      {
        case HashProvider.SHA1:
          return (HashAlgorithm) SHA1.Create();
        case HashProvider.SHA256:
          return (HashAlgorithm) SHA256.Create();
        case HashProvider.SHA384:
          return (HashAlgorithm) SHA384.Create();
        case HashProvider.SHA512:
          return (HashAlgorithm) SHA512.Create();
        case HashProvider.HMACSHA256:
          return (HashAlgorithm) new HMACSHA256();
        case HashProvider.HMACSHA384:
          return (HashAlgorithm) new HMACSHA384();
        case HashProvider.HMACSHA512:
          return (HashAlgorithm) new HMACSHA512();
        case HashProvider.HMACSHA1:
          return (HashAlgorithm) new HMACSHA1();
        default:
          return (HashAlgorithm) MD5.Create();
      }
    }

    public byte[] ComputeHash(HashProvider hashType, byte[] input)
    {
      return this.ComputeHash(hashType, input, (byte[]) null);
    }

    public byte[] ComputeHash(HashProvider hashType, byte[] input, byte[] key)
    {
      using (HashAlgorithm hashAlgorithm = this.GetHashAlgorithm(hashType))
      {
        if (key != null && hashAlgorithm is KeyedHashAlgorithm)
          ((KeyedHashAlgorithm) hashAlgorithm).Key = key;
        return hashAlgorithm.ComputeHash(input);
      }
    }

    public byte[] ComputeHashSalt(HashProvider hashType, byte[] input, string salt)
    {
      return this.ComputeHashSalt(hashType, input, (byte[]) null, salt);
    }

    public byte[] ComputeHashSalt(HashProvider hashType, byte[] input, byte[] key, string salt)
    {
      byte[] bytes = this._encodingMethod.GetBytes(salt);
      byte[] input1 = new byte[input.Length + bytes.Length];
      Buffer.BlockCopy((Array) input, 0, (Array) input1, 0, input.Length);
      Buffer.BlockCopy((Array) bytes, 0, (Array) input1, input.Length, bytes.Length);
      byte[] hash = this.ComputeHash(hashType, input1, key);
      byte[] numArray = new byte[hash.Length + bytes.Length];
      Buffer.BlockCopy((Array) hash, 0, (Array) numArray, 0, hash.Length);
      Buffer.BlockCopy((Array) bytes, 0, (Array) numArray, hash.Length, bytes.Length);
      return numArray;
    }

    public MemoryStream ComputeHash(HashProvider hashType, MemoryStream memStream)
    {
      byte[] array = memStream.ToArray();
      this.GetHashAlgorithm(hashType).ComputeHash(array);
      return new MemoryStream();
    }

    public byte[] ComputeHash(HashProvider hashType, string inputFile)
    {
      return this.ComputeHash(hashType, inputFile, (byte[]) null);
    }

    public byte[] ComputeHash(HashProvider hashType, string inputFile, byte[] key)
    {
      byte[] numArray;
      using (FileStream fileStream = new FileStream(inputFile, FileMode.Open))
      {
        numArray = new byte[fileStream.Length];
        fileStream.Read(numArray, 0, (int) fileStream.Length);
      }
      return this.ComputeHash(hashType, numArray, key);
    }

    public byte[] ComputeHash(HashProvider hashType, string inputFile, string salt)
    {
      return this.ComputeHash(hashType, inputFile, (byte[]) null, salt);
    }

    public byte[] ComputeHash(HashProvider hashType, string inputFile, byte[] key, string salt)
    {
      byte[] numArray;
      using (FileStream fileStream = new FileStream(inputFile, FileMode.Open))
      {
        numArray = new byte[fileStream.Length];
        fileStream.Read(numArray, 0, (int) fileStream.Length);
      }
      return this.ComputeHashSalt(hashType, numArray, key, salt);
    }
  }
}
