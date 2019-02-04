using System;
using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal abstract class BlockHashAlgorithm : HashAlgorithm
  {
    protected int State;
    private int blockSize;
    private byte[] buffer;
    private int bufferCount;
    private long count;

    public int BlockSize
    {
      get
      {
        return this.blockSize;
      }
    }

    public int BufferCount
    {
      get
      {
        return this.bufferCount;
      }
    }

    public long Count
    {
      get
      {
        return this.count;
      }
    }

    protected BlockHashAlgorithm(int blockSize)
    {
      this.blockSize = blockSize;
    }

    public override void Initialize()
    {
      lock (this)
      {
        this.count = 0L;
        this.bufferCount = 0;
        this.State = 0;
        this.buffer = new byte[this.BlockSize];
      }
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
      lock (this)
      {
        if (this.BufferCount > 0)
        {
          if (cbSize < this.BlockSize - this.BufferCount)
          {
            Array.Copy((Array) array, ibStart, (Array) this.buffer, this.BufferCount, cbSize);
            this.bufferCount += cbSize;
            return;
          }
          int length = this.BlockSize - this.BufferCount;
          Array.Copy((Array) array, ibStart, (Array) this.buffer, this.BufferCount, length);
          this.ProcessBlock(this.buffer, 0);
          this.count += (long) this.BlockSize;
          this.bufferCount = 0;
          ibStart += length;
          cbSize -= length;
        }
        int num = 0;
        while (num < cbSize - cbSize % this.BlockSize)
        {
          this.ProcessBlock(array, ibStart + num);
          this.count += (long) this.BlockSize;
          num += this.BlockSize;
        }
        int length1 = cbSize % this.BlockSize;
        if (length1 == 0)
          return;
        Array.Copy((Array) array, cbSize - length1 + ibStart, (Array) this.buffer, 0, length1);
        this.bufferCount = length1;
      }
    }

    protected override byte[] HashFinal()
    {
      lock (this)
        return this.ProcessFinalBlock(this.buffer, 0, this.bufferCount);
    }

    protected abstract void ProcessBlock(byte[] inputBuffer, int inputOffset);

    protected abstract byte[] ProcessFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
  }
}
