using System;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class QuotedPrintable
  {
    public string Encode(byte[] bytes, Encoding encoding)
    {
      int currentLineLength = 0;
      StringBuilder sb = new StringBuilder(bytes.Length);
      for (int index = 0; index < bytes.Length; ++index)
      {
        if (bytes[index] == (byte) 10 || bytes[index] == (byte) 13)
        {
          if (bytes[index] == (byte) 13 && this.GetNextByte(index, bytes, 1) == 10)
          {
            this.CheckLineLength(76, ref currentLineLength, 0, sb);
            sb.Append("\r\n");
            currentLineLength = 0;
            ++index;
          }
          else
          {
            if (bytes[index] == (byte) 10)
            {
              this.CheckLineLength(76, ref currentLineLength, 0, sb);
              sb.Append("\r\n");
              currentLineLength = 0;
            }
            if (bytes[index] == (byte) 13)
            {
              this.CheckLineLength(76, ref currentLineLength, 3, sb);
              sb.Append("=" + this.ConvertToHex(bytes[index]));
            }
          }
        }
        else if (bytes[index] >= (byte) 33 && bytes[index] <= (byte) 60 || bytes[index] >= (byte) 62 && bytes[index] <= (byte) 126)
        {
          this.CheckLineLength(76, ref currentLineLength, 1, sb);
          sb.Append(Convert.ToChar(bytes[index]));
        }
        else if (bytes[index] == (byte) 9 || bytes[index] == (byte) 32)
        {
          this.CheckLineLength(76, ref currentLineLength, 0, sb);
          sb.Append(Convert.ToChar(bytes[index]));
          ++currentLineLength;
        }
        else
        {
          this.CheckLineLength(76, ref currentLineLength, 3, sb);
          sb.Append("=" + this.ConvertToHex(bytes[index]));
        }
      }
      return sb.ToString();
    }

    private void CheckLineLength(int maxLineLength, ref int currentLineLength, int newStringLength, StringBuilder sb)
    {
      if (currentLineLength + 1 == maxLineLength || currentLineLength + newStringLength + 1 >= maxLineLength)
      {
        sb.Append("=\r\n");
        currentLineLength = newStringLength;
      }
      else
        currentLineLength += newStringLength;
    }

    private int GetNextByte(int index, byte[] bytes, int shiftValue)
    {
      int index1 = index + shiftValue;
      if (index1 < 0 || index1 > bytes.Length - 1 || bytes.Length == 0)
        return -1;
      return (int) bytes[index1];
    }

    private string ConvertToHex(byte number)
    {
      string upper = Convert.ToString(number, 16).ToUpper();
      if (upper.Length != 2)
        return "0" + upper;
      return upper;
    }
  }
}
