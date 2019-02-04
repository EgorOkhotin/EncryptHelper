using System;
using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal abstract class TigerBlockHashAlgorithm : HashAlgorithm
  {
    private byte[] ba_PartialBlockBuffer;
    private int i_PartialBlockFill;
    protected int i_InputBlockSize;
    protected long l_TotalBytesProcessed;
    protected internal byte[] HashValue;

    public new int HashSize { get; set; }

    protected TigerBlockHashAlgorithm(int blockSize, int hashSize)
    {
      this.i_InputBlockSize = blockSize;
      this.HashSize = hashSize;
      this.ba_PartialBlockBuffer = new byte[this.BlockSize];
    }

    public override void Initialize()
    {
      this.l_TotalBytesProcessed = 0L;
      this.i_PartialBlockFill = 0;
      if (this.ba_PartialBlockBuffer != null)
        return;
      this.ba_PartialBlockBuffer = new byte[this.BlockSize];
    }

    public int BlockSize
    {
      get
      {
        return this.i_InputBlockSize;
      }
    }

    public int BufferFill
    {
      get
      {
        return this.i_PartialBlockFill;
      }
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
      if (this.BufferFill > 0)
      {
        if (cbSize + this.BufferFill < this.BlockSize)
        {
          Array.Copy((Array) array, ibStart, (Array) this.ba_PartialBlockBuffer, this.BufferFill, cbSize);
          this.i_PartialBlockFill += cbSize;
          return;
        }
        int length = this.BlockSize - this.BufferFill;
        Array.Copy((Array) array, ibStart, (Array) this.ba_PartialBlockBuffer, this.BufferFill, length);
        this.ProcessBlock(this.ba_PartialBlockBuffer, 0, 1);
        this.l_TotalBytesProcessed += (long) this.BlockSize;
        this.i_PartialBlockFill = 0;
        ibStart += length;
        cbSize -= length;
      }
      if (cbSize >= this.BlockSize)
      {
        this.ProcessBlock(array, ibStart, cbSize / this.BlockSize);
        this.l_TotalBytesProcessed += (long) (cbSize - cbSize % this.BlockSize);
      }
      int length1 = cbSize % this.BlockSize;
      if (length1 == 0)
        return;
      Array.Copy((Array) array, cbSize - length1 + ibStart, (Array) this.ba_PartialBlockBuffer, 0, length1);
      this.i_PartialBlockFill = length1;
    }

    protected override byte[] HashFinal()
    {
      return this.ProcessFinalBlock(this.ba_PartialBlockBuffer, 0, this.i_PartialBlockFill);
    }

    protected abstract void ProcessBlock(byte[] inputBuffer, int inputOffset, int inputLength);

    protected abstract byte[] ProcessFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);

    internal static class BitTools
    {
      public static ushort RotLeft(ushort v, int b)
      {
        int num1 = (int) v << 16 | (int) v;
        b %= 16;
        int num2 = b & 31;
        return (ushort) ((uint) num1 >> num2);
      }

      public static uint RotLeft(uint v, int b)
      {
        long num1 = (long) v << 32 | (long) v;
        b %= 32;
        int num2 = 32 - b & 63;
        return (uint) ((ulong) num1 >> num2);
      }

      public static void TypeBlindCopy(byte[] sourceArray, int sourceIndex, uint[] destinationArray, int destinationIndex, int sourceLength)
      {
        if (sourceIndex + sourceLength > sourceArray.Length || destinationIndex + (sourceLength + 3) / 4 > destinationArray.Length || sourceLength % 4 != 0)
          throw new ArgumentException("BitTools.TypeBlindCopy: index or length boundary mismatch.");
        int num = 0;
        while (num < sourceLength)
        {
          destinationArray[destinationIndex] = BitConverter.ToUInt32(sourceArray, sourceIndex);
          num += 4;
          sourceIndex += 4;
          ++destinationIndex;
        }
      }

      public static void TypeBlindCopy(uint[] sourceArray, int sourceIndex, byte[] destinationArray, int destinationIndex, int sourceLength)
      {
        if (sourceIndex + sourceLength > sourceArray.Length || destinationIndex + sourceLength * 4 > destinationArray.Length)
          throw new ArgumentException("BitTools.TypeBlindCopy: index or length boundary mismatch.");
        int num = 0;
        while (num < sourceLength)
        {
          Array.Copy((Array) BitConverter.GetBytes(sourceArray[sourceIndex]), 0, (Array) destinationArray, destinationIndex, 4);
          ++num;
          ++sourceIndex;
          destinationIndex += 4;
        }
      }

      public static void TypeBlindCopy(byte[] sourceArray, int sourceIndex, ulong[] destinationArray, int destinationIndex, int sourceLength)
      {
        if (sourceIndex + sourceLength > sourceArray.Length || destinationIndex + (sourceLength + 7) / 8 > destinationArray.Length || sourceLength % 8 != 0)
          throw new ArgumentException("BitTools.TypeBlindCopy: index or length boundary mismatch.");
        int num = 0;
        while (num < sourceLength)
        {
          destinationArray[destinationIndex] = BitConverter.ToUInt64(sourceArray, sourceIndex);
          num += 8;
          sourceIndex += 8;
          ++destinationIndex;
        }
      }

      public static void TypeBlindCopy(ulong[] sourceArray, int sourceIndex, byte[] destinationArray, int destinationIndex, int sourceLength)
      {
        if (sourceIndex + sourceLength > sourceArray.Length || destinationIndex + sourceLength * 8 > destinationArray.Length)
          throw new ArgumentException("BitTools.TypeBlindCopy: index or length boundary mismatch.");
        int num = 0;
        while (num < sourceLength)
        {
          Array.Copy((Array) BitConverter.GetBytes(sourceArray[sourceIndex]), 0, (Array) destinationArray, destinationIndex, 8);
          ++num;
          ++sourceIndex;
          destinationIndex += 8;
        }
      }
    }
  }
}
