using System;
using System.IO;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal static class MiniLZO
  {
    private static readonly uint DICT_SIZE = 65539;
    private const byte BITS = 14;
    private const uint D_MASK = 16383;
    private const uint M2_MAX_LEN = 8;
    private const uint M2_MAX_OFFSET = 2048;
    private const byte M3_MARKER = 32;
    private const uint M3_MAX_OFFSET = 16384;
    private const byte M4_MARKER = 16;
    private const uint M4_MAX_LEN = 9;
    private const uint M4_MAX_OFFSET = 49151;

    static MiniLZO()
    {
      if (IntPtr.Size == 8)
        MiniLZO.DICT_SIZE = 131078U;
      else
        MiniLZO.DICT_SIZE = 65539U;
    }

    public static byte[] Compress(byte[] src)
    {
      if (src == null)
        return (byte[]) null;
      return MiniLZO.Compress(src, 0, src.Length);
    }

    public static byte[] Compress(byte[] src, int srcCount)
    {
      if (src == null)
        throw new ArgumentNullException(nameof (src));
      if (srcCount > src.Length)
        throw new ArgumentOutOfRangeException("src[] has length " + (object) src.Length + ", but srcCount was " + (object) srcCount);
      return MiniLZO.Compress(src, 0, srcCount);
    }

    public static byte[] Compress(byte[] src, int srcStart, int srcLength)
    {
      if (src == null)
        throw new ArgumentNullException(nameof (src));
      if (srcStart < 0)
        throw new ArgumentOutOfRangeException("srcStart was " + (object) srcStart);
      if (srcStart + srcLength > src.Length)
        throw new ArgumentOutOfRangeException("src[] has length " + (object) src.Length + ", but srcStart + srcLength was " + (object) (srcStart + srcLength));
      uint dstlen = (uint) (srcLength + srcLength / 16 + 64 + 3 + 4);
      byte[] dst = new byte[(int) dstlen];
      uint num = MiniLZO.Compress(src, (uint) srcStart, (uint) srcLength, dst, 0U, dstlen, (uint[]) null);
      if ((long) dst.Length != (long) num)
      {
        byte[] numArray = new byte[(int) num];
        Buffer.BlockCopy((Array) dst, 0, (Array) numArray, 0, (int) num);
        dst = numArray;
      }
      return dst;
    }

    public static byte[] Compress(MemoryStream source)
    {
      if (source == null)
        return (byte[]) null;
      ArraySegment<byte> buffer1;
      source.TryGetBuffer(out buffer1);
      byte[] array = buffer1.Array;
      int capacity = source.Capacity;
      uint length = (uint) source.Length;
      uint dstlen = (uint) ((int) length + (int) (length / 16U) + 64 + 3 + 4);
      int num1 = (int) length;
      int num2 = capacity - num1;
      uint num3 = (uint) ((int) Math.Min(length, 49151U) + (int) (length / 64U) + 16 + 3 + 4);
      int num4 = (int) num3;
      uint srcstart;
      byte[] dst;
      if ((uint) num2 < (uint) num4)
      {
        srcstart = 0U;
        dst = new byte[(int) dstlen];
      }
      else
      {
        srcstart = num3;
        source.SetLength((long) (length + num3));
        dst = array;
        Buffer.BlockCopy((Array) dst, 0, (Array) dst, (int) num3, (int) length);
      }
      uint num5 = MiniLZO.Compress(array, srcstart, length, dst, 0U, dstlen, (uint[]) null);
      if (dst == array)
      {
        source.SetLength((long) num5);
        source.Capacity = (int) num5;
        ArraySegment<byte> buffer2;
        source.TryGetBuffer(out buffer2);
        return buffer2.Array;
      }
      byte[] numArray = new byte[(int) num5];
      Buffer.BlockCopy((Array) dst, 0, (Array) numArray, 0, (int) num5);
      return numArray;
    }

    public static byte[] Decompress(byte[] src)
    {
      if (src == null)
        return (byte[]) null;
      byte[] numArray = new byte[(int) src[src.Length - 4] | (int) src[src.Length - 3] << 8 | ((int) src[src.Length - 2] << 16 | (int) src[src.Length - 1] << 24)];
      uint num1 = 0;
      uint num2 = (uint) (src.Length - 4);
      uint length = (uint) numArray.Length;
      uint index = 0;
      uint num3 = 0;
      bool flag1 = false;
      bool flag2 = false;
      bool flag3 = false;
      bool flag4 = false;
      bool flag5 = false;
      bool flag6 = false;
      if (src[(int) index] > (byte) 17)
      {
        num1 = (uint) src[(int) index] - 17U;
        ++index;
        if (num1 < 4U)
        {
          flag2 = true;
        }
        else
        {
          if (length - num3 < num1)
            throw new OverflowException("Output Overrun");
          if (num2 - index < num1 + 1U)
            throw new OverflowException("Input Overrun");
          do
          {
            numArray[(int) num3] = src[(int) index];
            ++num3;
            ++index;
          }
          while (--num1 > 0U);
          flag5 = true;
        }
      }
      while (!flag6 && index < num2)
      {
        if (!flag2 && !flag5)
        {
          num1 = (uint) src[(int) index];
          ++index;
          if (num1 >= 16U)
          {
            flag1 = true;
          }
          else
          {
            if (num1 == 0U)
            {
              if (num2 - index < 1U)
                throw new OverflowException("Input Overrun");
              while (src[(int) index] == (byte) 0)
              {
                num1 += (uint) byte.MaxValue;
                ++index;
                if (num2 - index < 1U)
                  throw new OverflowException("Input Overrun");
              }
              num1 += 15U + (uint) src[(int) index];
              ++index;
            }
            if (length - num3 < num1 + 3U)
              throw new OverflowException("Output Overrun");
            if (num2 - index < num1 + 4U)
              throw new OverflowException("Input Overrun");
            int num4 = 0;
            while (num4 < 4)
            {
              numArray[(int) num3] = src[(int) index];
              ++num4;
              ++num3;
              ++index;
            }
            if (--num1 > 0U)
            {
              if (num1 >= 4U)
              {
                do
                {
                  int num5 = 0;
                  while (num5 < 4)
                  {
                    numArray[(int) num3] = src[(int) index];
                    ++num5;
                    ++num3;
                    ++index;
                  }
                  num1 -= 4U;
                }
                while (num1 >= 4U);
                if (num1 > 0U)
                {
                  do
                  {
                    numArray[(int) num3] = src[(int) index];
                    ++num3;
                    ++index;
                  }
                  while (--num1 > 0U);
                }
              }
              else
              {
                do
                {
                  numArray[(int) num3] = src[(int) index];
                  ++num3;
                  ++index;
                }
                while (--num1 > 0U);
              }
            }
          }
        }
        if (!flag1 && !flag2)
        {
          flag5 = false;
          num1 = (uint) src[(int) index];
          ++index;
          if (num1 < 16U)
          {
            uint num4 = num3 - 2049U - (num1 >> 2) - ((uint) src[(int) index] << 2);
            ++index;
            if (num4 < 0U || num4 >= num3)
              throw new OverflowException("Lookbehind Overrun");
            if (length - num3 < 3U)
              throw new OverflowException("Output Overrun");
            numArray[(int) num3] = numArray[(int) num4];
            uint num5 = num3 + 1U;
            uint num6 = num4 + 1U;
            numArray[(int) num5] = numArray[(int) num6];
            uint num7 = num5 + 1U;
            uint num8 = num6 + 1U;
            numArray[(int) num7] = numArray[(int) num8];
            num3 = num7 + 1U;
            uint num9 = num8 + 1U;
            flag3 = true;
          }
        }
        flag1 = false;
label_46:
        uint num10;
        if (num1 >= 64U)
        {
          num10 = num3 - 1U - (num1 >> 2 & 7U) - ((uint) src[(int) index] << 3);
          ++index;
          num1 = (num1 >> 5) - 1U;
          if (num10 < 0U || num10 >= num3)
            throw new OverflowException("Lookbehind Overrun");
          if (length - num3 < num1 + 2U)
            throw new OverflowException("Output Overrun");
          flag4 = true;
        }
        else if (num1 >= 32U)
        {
          num1 &= 31U;
          if (num1 == 0U)
          {
            if (num2 - index < 1U)
              throw new OverflowException("Input Overrun");
            while (src[(int) index] == (byte) 0)
            {
              num1 += (uint) byte.MaxValue;
              ++index;
              if (num2 - index < 1U)
                throw new OverflowException("Input Overrun");
            }
            num1 += 31U + (uint) src[(int) index];
            ++index;
          }
          num10 = num3 - 1U - ((uint) MiniLZO.GetUShortFrom2Bytes(src, index) >> 2);
          index += 2U;
        }
        else if (num1 >= 16U)
        {
          uint num4 = num3 - (uint) (((int) num1 & 8) << 11);
          num1 &= 7U;
          if (num1 == 0U)
          {
            if (num2 - index < 1U)
              throw new OverflowException("Input Overrun");
            while (src[(int) index] == (byte) 0)
            {
              num1 += (uint) byte.MaxValue;
              ++index;
              if (num2 - index < 1U)
                throw new OverflowException("Input Overrun");
            }
            num1 += 7U + (uint) src[(int) index];
            ++index;
          }
          num10 = num4 - ((uint) MiniLZO.GetUShortFrom2Bytes(src, index) >> 2);
          index += 2U;
          if ((int) num10 == (int) num3)
            flag6 = true;
          else
            num10 -= 16384U;
        }
        else
        {
          uint num4 = num3 - 1U - (num1 >> 2) - ((uint) src[(int) index] << 2);
          ++index;
          if (num4 < 0U || num4 >= num3)
            throw new OverflowException("Lookbehind Overrun");
          if (length - num3 < 2U)
            throw new OverflowException("Output Overrun");
          numArray[(int) num3] = numArray[(int) num4];
          uint num5 = num3 + 1U;
          uint num6 = num4 + 1U;
          numArray[(int) num5] = numArray[(int) num6];
          num3 = num5 + 1U;
          num10 = num6 + 1U;
          flag3 = true;
        }
        if (!flag6 && !flag3 && !flag4)
        {
          if (num10 < 0U || num10 >= num3)
            throw new OverflowException("Lookbehind Overrun");
          if (length - num3 < num1 + 2U)
            throw new OverflowException("Output Overrun");
        }
        if (!flag6 && num1 >= 6U && (num3 - num10 >= 4U && !flag3) && !flag4)
        {
          int num4 = 0;
          while (num4 < 4)
          {
            numArray[(int) num3] = numArray[(int) num10];
            ++num4;
            ++num3;
            ++num10;
          }
          num1 -= 2U;
          do
          {
            int num5 = 0;
            while (num5 < 4)
            {
              numArray[(int) num3] = numArray[(int) num10];
              ++num5;
              ++num3;
              ++num10;
            }
            num1 -= 4U;
          }
          while (num1 >= 4U);
          if (num1 > 0U)
          {
            do
            {
              numArray[(int) num3] = numArray[(int) num10];
              ++num3;
              ++num10;
            }
            while (--num1 > 0U);
          }
        }
        else if (!flag6 && !flag3)
        {
          flag4 = false;
          numArray[(int) num3] = numArray[(int) num10];
          uint num4 = num3 + 1U;
          uint num5 = num10 + 1U;
          numArray[(int) num4] = numArray[(int) num5];
          num3 = num4 + 1U;
          uint num6 = num5 + 1U;
          do
          {
            numArray[(int) num3] = numArray[(int) num6];
            ++num3;
            ++num6;
          }
          while (--num1 > 0U);
        }
        if (!flag6 && !flag2)
        {
          flag3 = false;
          num1 = (uint) src[(int) index - 2] & 3U;
          if (num1 == 0U)
            continue;
        }
        if (!flag6)
        {
          flag2 = false;
          if (length - num3 < num1)
            throw new OverflowException("Output Overrun");
          if (num2 - index < num1 + 1U)
            throw new OverflowException("Input Overrun");
          numArray[(int) num3] = src[(int) index];
          ++num3;
          uint num4 = index + 1U;
          if (num1 > 1U)
          {
            numArray[(int) num3] = src[(int) num4];
            ++num3;
            ++num4;
            if (num1 > 2U)
            {
              numArray[(int) num3] = src[(int) num4];
              ++num3;
              ++num4;
            }
          }
          num1 = (uint) src[(int) num4];
          index = num4 + 1U;
        }
        if (!flag6 && index < num2)
          goto label_46;
      }
      if (!flag6)
        throw new OverflowException("EOF Marker Not Found");
      if (index > num2)
        throw new OverflowException("Input Overrun");
      if (index < num2)
        throw new OverflowException("Input Not Consumed");
      return numArray;
    }

    private static uint Compress(byte[] src, uint srcstart, uint srcLength, byte[] dst, uint dststart, uint dstlen, uint[] dictNew)
    {
      if (dictNew == null)
        dictNew = new uint[(int) MiniLZO.DICT_SIZE];
      uint num1;
      if (srcLength <= 13U)
      {
        num1 = srcLength;
        dstlen = 0U;
      }
      else
      {
        uint num2 = srcstart + srcLength;
        uint num3 = (uint) ((int) srcstart + (int) srcLength - 8 - 5);
        uint num4 = srcstart;
        uint num5 = srcstart + 4U;
        uint num6 = dststart;
        bool flag1 = false;
        bool flag2 = false;
        do
        {
          uint num7 = 0;
          uint idx = MiniLZO.D_INDEX1(src, num5);
          uint index1 = num5 - (num5 - dictNew[(int) idx]);
          if (index1 < srcstart || (num7 = num5 - index1) <= 0U || num7 > 49151U)
            flag1 = true;
          else if (num7 > 2048U && (int) src[(int) index1 + 3] != (int) src[(int) num5 + 3])
          {
            idx = MiniLZO.D_INDEX2(idx);
            index1 = num5 - (num5 - dictNew[(int) idx]);
            if (index1 < srcstart || (num7 = num5 - index1) <= 0U || num7 > 49151U)
              flag1 = true;
            else if (num7 > 2048U && (int) src[(int) index1 + 3] != (int) src[(int) num5 + 3])
              flag1 = true;
          }
          if (!flag1 && (int) MiniLZO.GetUShortFrom2Bytes(src, index1) == (int) MiniLZO.GetUShortFrom2Bytes(src, num5) && (int) src[(int) index1 + 2] == (int) src[(int) num5 + 2])
            flag2 = true;
          flag1 = false;
          if (!flag2)
          {
            dictNew[(int) idx] = num5;
            ++num5;
            if (num5 >= num3)
              break;
          }
          else
          {
            flag2 = false;
            dictNew[(int) idx] = num5;
            if (num5 - num4 > 0U)
            {
              uint num8 = num5 - num4;
              if (num8 <= 3U)
                dst[(int) num6 - 2] |= (byte) num8;
              else if (num8 <= 18U)
              {
                dst[(int) num6] = (byte) (num8 - 3U);
                ++num6;
              }
              else
              {
                uint num9 = num8 - 18U;
                dst[(int) num6] = (byte) 0;
                uint num10 = num6 + 1U;
                while (num9 > (uint) byte.MaxValue)
                {
                  num9 -= (uint) byte.MaxValue;
                  dst[(int) num10] = (byte) 0;
                  ++num10;
                }
                dst[(int) num10] = (byte) num9;
                num6 = num10 + 1U;
              }
              do
              {
                dst[(int) num6] = src[(int) num4];
                ++num6;
                ++num4;
              }
              while (--num8 > 0U);
            }
            uint num11 = num5 + 3U;
            int num12 = (int) src[(int) index1 + 3];
            byte[] numArray = src;
            int index2 = (int) num11;
            num5 = (uint) (index2 + 1);
            int num13 = (int) numArray[index2];
            if (num12 != num13 || (int) src[(int) index1 + 4] != (int) src[(int) num5++] || ((int) src[(int) index1 + 5] != (int) src[(int) num5++] || (int) src[(int) index1 + 6] != (int) src[(int) num5++]) || ((int) src[(int) index1 + 7] != (int) src[(int) num5++] || (int) src[(int) index1 + 8] != (int) src[(int) num5++]))
            {
              --num5;
              uint num8 = num5 - num4;
              if (num7 <= 2048U)
              {
                uint num9 = num7 - 1U;
                dst[(int) num6] = (byte) ((int) num8 - 1 << 5 | ((int) num9 & 7) << 2);
                uint num10 = num6 + 1U;
                dst[(int) num10] = (byte) (num9 >> 3);
                num6 = num10 + 1U;
              }
              else if (num7 <= 16384U)
              {
                uint num9 = num7 - 1U;
                dst[(int) num6] = (byte) (32 | (int) num8 - 2);
                uint num10 = num6 + 1U;
                dst[(int) num10] = (byte) (((int) num9 & 63) << 2);
                uint num14 = num10 + 1U;
                dst[(int) num14] = (byte) (num9 >> 6);
                num6 = num14 + 1U;
              }
              else
              {
                uint num9 = num7 - 16384U;
                dst[(int) num6] = (byte) (16 | (int) ((num9 & 16384U) >> 11) | (int) num8 - 2);
                uint num10 = num6 + 1U;
                dst[(int) num10] = (byte) (((int) num9 & 63) << 2);
                uint num14 = num10 + 1U;
                dst[(int) num14] = (byte) (num9 >> 6);
                num6 = num14 + 1U;
              }
            }
            else
            {
              for (uint index3 = (uint) ((int) index1 + 8 + 1); num5 < num2 && (int) src[(int) index3] == (int) src[(int) num5]; ++num5)
                ++index3;
              uint num8 = num5 - num4;
              uint num9;
              uint num10;
              if (num7 <= 16384U)
              {
                num9 = num7 - 1U;
                if (num8 <= 33U)
                {
                  dst[(int) num6] = (byte) (32 | (int) num8 - 2);
                  num10 = num6 + 1U;
                }
                else
                {
                  uint num14 = num8 - 33U;
                  dst[(int) num6] = (byte) 32;
                  uint num15 = num6 + 1U;
                  while (num14 > (uint) byte.MaxValue)
                  {
                    num14 -= (uint) byte.MaxValue;
                    dst[(int) num15] = (byte) 0;
                    ++num15;
                  }
                  dst[(int) num15] = (byte) num14;
                  num10 = num15 + 1U;
                }
              }
              else
              {
                num9 = num7 - 16384U;
                if (num8 <= 9U)
                {
                  dst[(int) num6] = (byte) (16 | (int) ((num9 & 16384U) >> 11) | (int) num8 - 2);
                  num10 = num6 + 1U;
                }
                else
                {
                  uint num14 = num8 - 9U;
                  dst[(int) num6] = (byte) (16U | (num9 & 16384U) >> 11);
                  uint num15 = num6 + 1U;
                  while (num14 > (uint) byte.MaxValue)
                  {
                    num14 -= (uint) byte.MaxValue;
                    dst[(int) num15] = (byte) 0;
                    ++num15;
                  }
                  dst[(int) num15] = (byte) num14;
                  num10 = num15 + 1U;
                }
              }
              dst[(int) num10] = (byte) (((int) num9 & 63) << 2);
              uint num16 = num10 + 1U;
              dst[(int) num16] = (byte) (num9 >> 6);
              num6 = num16 + 1U;
            }
            num4 = num5;
          }
        }
        while (num5 < num3);
        dstlen = num6 - dststart;
        num1 = num2 - num4;
      }
      if (num1 > 0U)
      {
        uint num2 = srcLength - num1 + srcstart;
        if (dstlen == 0U && num1 <= 238U)
          dst[(int) dstlen++] = (byte) (17U + num1);
        else if (num1 <= 3U)
          dst[(int) dstlen - 2] |= (byte) num1;
        else if (num1 <= 18U)
        {
          dst[(int) dstlen++] = (byte) (num1 - 3U);
        }
        else
        {
          uint num3 = num1 - 18U;
          dst[(int) dstlen++] = (byte) 0;
          while (num3 > (uint) byte.MaxValue)
          {
            num3 -= (uint) byte.MaxValue;
            dst[(int) dstlen++] = (byte) 0;
          }
          dst[(int) dstlen++] = (byte) num3;
        }
        do
        {
          dst[(int) dstlen++] = src[(int) num2++];
        }
        while (--num1 > 0U);
      }
      dst[(int) dstlen++] = (byte) 17;
      dst[(int) dstlen++] = (byte) 0;
      dst[(int) dstlen++] = (byte) 0;
      dst[(int) dstlen++] = (byte) srcLength;
      dst[(int) dstlen++] = (byte) (srcLength >> 8);
      dst[(int) dstlen++] = (byte) (srcLength >> 16);
      dst[(int) dstlen++] = (byte) (srcLength >> 24);
      return dstlen;
    }

    private static uint D_INDEX1(byte[] src, int input)
    {
      return MiniLZO.D_MS(MiniLZO.D_MUL(33U, MiniLZO.D_X3(src, input, (byte) 5, (byte) 5, (byte) 6)) >> 5, (byte) 0);
    }

    private static uint D_INDEX1(byte[] src, uint input)
    {
      byte num1 = src[(int) input + 2];
      byte num2 = src[(int) input + 1];
      byte num3 = src[(int) input];
      return 16383U & ((uint) (33 * ((((int) num1 << 6 ^ (int) num2) << 5 ^ (int) num3) << 5)) ^ (uint) num3) >> 5;
    }

    private static uint D_INDEX2(uint idx)
    {
      return (uint) ((int) idx & 2047 ^ 8223);
    }

    private static uint D_MS(uint v, byte s)
    {
      return (v & 16383U >> (int) s) << (int) s;
    }

    private static uint D_MUL(uint a, uint b)
    {
      return a * b;
    }

    private static uint D_X2(byte[] src, int input, byte s1, byte s2)
    {
      return ((uint) src[input + 2] << (int) s2 ^ (uint) src[input + 1]) << (int) s1 ^ (uint) src[input];
    }

    private static uint D_X3(byte[] src, int input, byte s1, byte s2, byte s3)
    {
      return MiniLZO.D_X2(src, input + 1, s2, s3) << (int) s1 ^ (uint) src[input];
    }

    private static uint D_X2(byte[] src, uint input, byte s1, byte s2)
    {
      return ((uint) src[(int) input + 2] << (int) s2 ^ (uint) src[(int) input + 1]) << (int) s1 ^ (uint) src[(int) input];
    }

    private static uint D_X3(byte[] src, uint input, byte s1, byte s2, byte s3)
    {
      return MiniLZO.D_X2(src, input + 1U, s2, s3) << (int) s1 ^ (uint) src[(int) input];
    }

    private static ushort GetUShortFrom2Bytes(byte[] workmem, uint index)
    {
      return (ushort) ((uint) workmem[(int) index] + (uint) workmem[(int) index + 1] * 256U);
    }
  }
}
