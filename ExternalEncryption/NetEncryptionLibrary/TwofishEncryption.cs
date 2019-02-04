using System;
using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class TwofishEncryption : TwofishBase, ICryptoTransform, IDisposable
  {
    private bool canReuseTransform = true;
    private byte[] m_dataBlock;
    private bool canTransformMultipleBlocks;
    private TwofishBase.EncryptionDirection encryptionDirection;

    public TwofishEncryption(int keyLen, ref byte[] key, ref byte[] iv, CipherMode cMode, TwofishBase.EncryptionDirection direction)
    {
      for (int index = 0; index < key.Length / 4; ++index)
        this.Key[index] = (uint) ((int) key[index * 4 + 3] << 24 | (int) key[index * 4 + 2] << 16 | (int) key[index * 4 + 1] << 8) | (uint) key[index * 4];
      this.cipherMode = cMode;
      if (this.cipherMode == CipherMode.CBC)
      {
        for (int index = 0; index < 4; ++index)
          this.IV[index] = (uint) ((int) iv[index * 4 + 3] << 24 | (int) iv[index * 4 + 2] << 16 | (int) iv[index * 4 + 1] << 8) | (uint) iv[index * 4];
      }
      this.encryptionDirection = direction;
      this.reKey(keyLen, ref this.Key);
    }

    public void Dispose()
    {
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
      uint[] x = new uint[4];
      for (int index = 0; index < 4; ++index)
        x[index] = (uint) ((int) inputBuffer[index * 4 + 3 + inputOffset] << 24 | (int) inputBuffer[index * 4 + 2 + inputOffset] << 16 | (int) inputBuffer[index * 4 + 1 + inputOffset] << 8) | (uint) inputBuffer[index * 4 + inputOffset];
      if (this.encryptionDirection == TwofishBase.EncryptionDirection.Encrypting)
        this.blockEncrypt(ref x);
      else
        this.blockDecrypt(ref x);
      for (int index = 0; index < 4; ++index)
      {
        outputBuffer[index * 4 + outputOffset] = TwofishBase.b0(x[index]);
        outputBuffer[index * 4 + 1 + outputOffset] = TwofishBase.b1(x[index]);
        outputBuffer[index * 4 + 2 + outputOffset] = TwofishBase.b2(x[index]);
        outputBuffer[index * 4 + 3 + outputOffset] = TwofishBase.b3(x[index]);
      }
      if (this.encryptionDirection == TwofishBase.EncryptionDirection.Decrypting)
      {
        byte[] numArray = new byte[outputBuffer.Length];
        Buffer.BlockCopy((Array) outputBuffer, 0, (Array) numArray, 0, outputBuffer.Length);
        if (this.m_dataBlock == null)
          outputBuffer = new byte[0];
        else
          Buffer.BlockCopy((Array) this.m_dataBlock, 0, (Array) outputBuffer, 0, outputBuffer.Length);
        this.m_dataBlock = numArray;
      }
      return outputBuffer.Length;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
      switch (this.encryptionDirection)
      {
        case TwofishBase.EncryptionDirection.Encrypting:
          inputBuffer[inputCount++] = byte.MaxValue;
          break;
        case TwofishBase.EncryptionDirection.Decrypting:
          int count = 16;
          do
            ;
          while (this.m_dataBlock[--count] != byte.MaxValue);
          byte[] numArray1 = new byte[count];
          Buffer.BlockCopy((Array) this.m_dataBlock, 0, (Array) numArray1, 0, count);
          return numArray1;
      }
      byte[] numArray2;
      if (inputCount > 0)
      {
        numArray2 = new byte[16];
        uint[] x = new uint[4];
        for (int index = 0; index < 4; ++index)
          x[index] = (uint) ((int) inputBuffer[index * 4 + 3] << 24 | (int) inputBuffer[index * 4 + 2] << 16 | (int) inputBuffer[index * 4 + 1] << 8) | (uint) inputBuffer[index * 4];
        if (this.encryptionDirection == TwofishBase.EncryptionDirection.Encrypting)
          this.blockEncrypt(ref x);
        else
          this.blockDecrypt(ref x);
        for (int index = 0; index < 4; ++index)
        {
          numArray2[index * 4] = TwofishBase.b0(x[index]);
          numArray2[index * 4 + 1] = TwofishBase.b1(x[index]);
          numArray2[index * 4 + 2] = TwofishBase.b2(x[index]);
          numArray2[index * 4 + 3] = TwofishBase.b3(x[index]);
        }
      }
      else
        numArray2 = new byte[0];
      return numArray2;
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
