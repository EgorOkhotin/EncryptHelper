using System;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary
{
  public static class Common
  {
    public static byte[] PrefixBytes = Encoding.ASCII.GetBytes("@KS@");
    public static int PrefixLength = Common.PrefixBytes.Length;
    public static Random random = new Random();
    public const string ENCRYPTION_PREFIX = "@KS@";

    public static string RandomString(int length)
    {
      StringBuilder stringBuilder = new StringBuilder(length);
      for (int index = 0; index < length - 1; ++index)
      {
        int startIndex = Common.random.Next(0, "ABCDEFGHIJKLMNOPQRSTUVWZYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()_+`-={}|[]\\:\";'<>?,./".Length - 1);
        stringBuilder.Append("ABCDEFGHIJKLMNOPQRSTUVWZYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()_+`-={}|[]\\:\";'<>?,./".Substring(startIndex, 1));
      }
      return stringBuilder.ToString();
    }

    public static bool PrefixMatch(byte[] inputBytes)
    {
      if (inputBytes == null || inputBytes.Length < Common.PrefixLength)
        return false;
      for (int index = 0; index < Common.PrefixLength; ++index)
      {
        if ((int) inputBytes[index] != (int) Common.PrefixBytes[index])
          return false;
      }
      return true;
    }

    public static void CopyByteArray(byte[] source, ref byte[] dest, int sourceStart, int destStart)
    {
      int index1 = sourceStart;
      int index2 = destStart;
      while (index1 < source.Length)
      {
        dest[index2] = source[index1];
        ++index1;
        ++index2;
      }
    }
  }
}
