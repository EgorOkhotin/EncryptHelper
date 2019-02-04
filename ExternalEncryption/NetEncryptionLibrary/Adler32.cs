using System;
using System.IO;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class Adler32
  {
    private static readonly uint BASE = 65521;
    private uint _checksum;

    public uint Checksum
    {
      get
      {
        return this._checksum;
      }
    }

    public Adler32()
    {
      this.Reset();
    }

    public void Reset()
    {
      this._checksum = 1U;
    }

    public uint GetStringAdler32(string myString)
    {
      byte[] bytes = Encoding.ASCII.GetBytes(myString);
      this.Process(bytes, 0, bytes.Length);
      return this.Checksum;
    }

    public uint GetStreamAdler32(Stream stream)
    {
      byte[] buffer = new byte[1024];
      while (true)
      {
        int length = stream.Read(buffer, 0, 1024);
        if (length != 0)
          this.Process(buffer, 0, length);
        else
          break;
      }
      return this.Checksum;
    }

    public uint GetFileAdler32(string filePath)
    {
      using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        return this.GetStreamAdler32((Stream) fileStream);
    }

    public void Process(int value)
    {
      uint num1 = this._checksum & (uint) ushort.MaxValue;
      uint num2 = this._checksum >> 16;
      uint num3 = (num1 + (uint) (value & (int) byte.MaxValue)) % Adler32.BASE;
      this._checksum = ((num3 + num2) % Adler32.BASE << 16) + num3;
    }

    public void Process(byte[] buffer)
    {
      this.Process(buffer, 0, buffer.Length);
    }

    public void Process(byte[] buffer, int start, int length)
    {
      if (buffer == null)
        throw new ArgumentNullException(nameof (buffer));
      if (start < 0 || length < 0 || start + length > buffer.Length)
        throw new ArgumentOutOfRangeException();
      uint num1 = this._checksum & (uint) ushort.MaxValue;
      uint num2 = this._checksum >> 16;
      while (length > 0)
      {
        int num3 = 3800;
        if (num3 > length)
          num3 = length;
        length -= num3;
        while (--num3 >= 0)
        {
          num1 += (uint) buffer[start++] & (uint) byte.MaxValue;
          num2 += num1;
        }
        num1 %= Adler32.BASE;
        num2 %= Adler32.BASE;
      }
      this._checksum = num2 << 16 | num1;
    }
  }
}
