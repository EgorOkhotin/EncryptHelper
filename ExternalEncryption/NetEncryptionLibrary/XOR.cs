using System;
using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class XOR : SymmetricAlgorithm, ICryptoTransform, IDisposable
  {
    private bool canReuseTransform = true;
    private int inputBlockSize = 16;
    private int outputBlockSize = 16;
    private bool canTransformMultipleBlocks;

    public XOR()
    {
      this.LegalKeySizesValue = new KeySizes[1]
      {
        new KeySizes(128, 128, 0)
      };
      this.KeySize = 128;
      this.LegalBlockSizesValue = new KeySizes[1]
      {
        new KeySizes(128, 128, 0)
      };
      this.BlockSize = 128;
    }

    public override ICryptoTransform CreateEncryptor(byte[] key, byte[] iv)
    {
      key.CopyTo((Array) this.Key, 0);
      iv.CopyTo((Array) this.IV, 0);
      return (ICryptoTransform) this;
    }

    public override ICryptoTransform CreateDecryptor(byte[] key, byte[] iv)
    {
      key.CopyTo((Array) this.Key, 0);
      iv.CopyTo((Array) this.IV, 0);
      return (ICryptoTransform) this;
    }

    public override void GenerateIV()
    {
      this.IV = new byte[16]
      {
        (byte) 0,
        (byte) 1,
        (byte) 2,
        (byte) 3,
        (byte) 4,
        (byte) 5,
        (byte) 6,
        (byte) 7,
        (byte) 8,
        (byte) 9,
        (byte) 10,
        (byte) 11,
        (byte) 12,
        (byte) 13,
        (byte) 14,
        (byte) 15
      };
    }

    public override void GenerateKey()
    {
      this.Key = new byte[16]
      {
        (byte) 0,
        (byte) 1,
        (byte) 2,
        (byte) 3,
        (byte) 4,
        (byte) 5,
        (byte) 6,
        (byte) 7,
        (byte) 8,
        (byte) 9,
        (byte) 10,
        (byte) 11,
        (byte) 12,
        (byte) 13,
        (byte) 14,
        (byte) 15
      };
    }

    public new void Dispose()
    {
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
      for (int index = 0; index < inputCount; ++index)
        outputBuffer[index + outputOffset] = (byte) ((uint) inputBuffer[index + inputOffset] ^ (uint) this.Key[index]);
      return inputCount;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
      byte[] numArray = new byte[inputCount];
      for (int index = 0; index < inputCount; ++index)
        numArray[index] = (byte) ((uint) inputBuffer[index + inputOffset] ^ (uint) this.Key[index]);
      return numArray;
    }

    public bool CanReuseTransform
    {
      get
      {
        return this.canReuseTransform;
      }
    }

    public bool CanTransformMultipleBlocks
    {
      get
      {
        return this.canTransformMultipleBlocks;
      }
    }

    public int InputBlockSize
    {
      get
      {
        return this.inputBlockSize;
      }
    }

    public int OutputBlockSize
    {
      get
      {
        return this.outputBlockSize;
      }
    }
  }
}
