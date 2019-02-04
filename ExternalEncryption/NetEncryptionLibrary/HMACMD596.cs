using System;
using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class HMACMD596 : HMACMD5
  {
    private const int _digestSize = 12;

    public override int HashSize
    {
      get
      {
        return 96;
      }
    }

    protected override byte[] HashFinal()
    {
      byte[] numArray1 = base.HashFinal();
      byte[] numArray2 = new byte[12];
      int srcOffset = 0;
      byte[] numArray3 = numArray2;
      int dstOffset = 0;
      int count = 12;
      Buffer.BlockCopy((Array) numArray1, srcOffset, (Array) numArray3, dstOffset, count);
      return numArray2;
    }
  }
}
