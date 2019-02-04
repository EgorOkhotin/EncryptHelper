using System;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class Utilities
  {
    private Utilities()
    {
    }

    [CLSCompliant(false)]
    public static ulong[] ByteToULong(byte[] array)
    {
      return Utilities.ByteToULong(array, 0, array.Length, EndianType.LittleEndian);
    }

    [CLSCompliant(false)]
    public static ulong[] ByteToULong(byte[] array, EndianType endian)
    {
      return Utilities.ByteToULong(array, 0, array.Length, endian);
    }

    [CLSCompliant(false)]
    public static ulong[] ByteToULong(byte[] array, int offset, int length)
    {
      return Utilities.ByteToULong(array, offset, length, EndianType.LittleEndian);
    }

    [CLSCompliant(false)]
    public static ulong[] ByteToULong(byte[] array, int offset, int length, EndianType endian)
    {
      if (length + offset > array.Length)
        throw new Exception("The length and offset provided extend past the end of the array.");
      if (length % 8 != 0)
        throw new ArgumentException("The number of bytes to convert must be a multiple of 8.", nameof (length));
      ulong[] numArray1 = new ulong[length / 8];
      int num1 = 0;
      int num2 = offset;
      for (; num1 < numArray1.Length; ++num1)
      {
        if (endian == EndianType.LittleEndian)
        {
          ulong[] numArray2 = numArray1;
          int index1 = num1;
          byte[] numArray3 = array;
          int index2 = num2;
          int num3 = index2 + 1;
          int num4 = (int) numArray3[index2] & (int) byte.MaxValue;
          byte[] numArray4 = array;
          int index3 = num3;
          int num5 = index3 + 1;
          int num6 = ((int) numArray4[index3] & (int) byte.MaxValue) << 8;
          int num7 = num4 | num6;
          byte[] numArray5 = array;
          int index4 = num5;
          int num8 = index4 + 1;
          int num9 = ((int) numArray5[index4] & (int) byte.MaxValue) << 16;
          int num10 = num7 | num9;
          byte[] numArray6 = array;
          int index5 = num8;
          int num11 = index5 + 1;
          int num12 = ((int) numArray6[index5] & (int) byte.MaxValue) << 24;
          int num13 = num10 | num12;
          byte[] numArray7 = array;
          int index6 = num11;
          int num14 = index6 + 1;
          int num15 = (int) numArray7[index6] & (int) byte.MaxValue;
          int num16 = num13 | num15;
          byte[] numArray8 = array;
          int index7 = num14;
          int num17 = index7 + 1;
          int num18 = ((int) numArray8[index7] & (int) byte.MaxValue) << 8;
          int num19 = num16 | num18;
          byte[] numArray9 = array;
          int index8 = num17;
          int num20 = index8 + 1;
          int num21 = ((int) numArray9[index8] & (int) byte.MaxValue) << 16;
          int num22 = num19 | num21;
          byte[] numArray10 = array;
          int index9 = num20;
          num2 = index9 + 1;
          int num23 = ((int) numArray10[index9] & (int) byte.MaxValue) << 24;
          long num24 = (long) (num22 | num23);
          numArray2[index1] = (ulong) num24;
        }
        else
        {
          ulong[] numArray2 = numArray1;
          int index1 = num1;
          byte[] numArray3 = array;
          int index2 = num2;
          int num3 = index2 + 1;
          int num4 = ((int) numArray3[index2] & (int) byte.MaxValue) << 24;
          byte[] numArray4 = array;
          int index3 = num3;
          int num5 = index3 + 1;
          int num6 = ((int) numArray4[index3] & (int) byte.MaxValue) << 16;
          int num7 = num4 | num6;
          byte[] numArray5 = array;
          int index4 = num5;
          int num8 = index4 + 1;
          int num9 = ((int) numArray5[index4] & (int) byte.MaxValue) << 8;
          int num10 = num7 | num9;
          byte[] numArray6 = array;
          int index5 = num8;
          int num11 = index5 + 1;
          int num12 = (int) numArray6[index5] & (int) byte.MaxValue;
          int num13 = num10 | num12;
          byte[] numArray7 = array;
          int index6 = num11;
          int num14 = index6 + 1;
          int num15 = ((int) numArray7[index6] & (int) byte.MaxValue) << 24;
          int num16 = num13 | num15;
          byte[] numArray8 = array;
          int index7 = num14;
          int num17 = index7 + 1;
          int num18 = ((int) numArray8[index7] & (int) byte.MaxValue) << 16;
          int num19 = num16 | num18;
          byte[] numArray9 = array;
          int index8 = num17;
          int num20 = index8 + 1;
          int num21 = ((int) numArray9[index8] & (int) byte.MaxValue) << 8;
          int num22 = num19 | num21;
          byte[] numArray10 = array;
          int index9 = num20;
          num2 = index9 + 1;
          int num23 = (int) numArray10[index9] & (int) byte.MaxValue;
          long num24 = (long) (num22 | num23);
          numArray2[index1] = (ulong) num24;
        }
      }
      return numArray1;
    }

    [CLSCompliant(false)]
    public static uint[] ByteToUInt(byte[] array, int offset, int length)
    {
      return Utilities.ByteToUInt(array, offset, length, EndianType.LittleEndian);
    }

    [CLSCompliant(false)]
    public static uint[] ByteToUInt(byte[] array, int offset, int length, EndianType endian)
    {
      if (length + offset > array.Length)
        throw new Exception("The length and offset provided extend past the end of the array.");
      if (length % 4 != 0)
        throw new ArgumentException("The number of bytes to convert must be a multiple of 4.", nameof (length));
      uint[] numArray1 = new uint[length / 4];
      int num1 = 0;
      int num2 = offset;
      for (; num1 < numArray1.Length; ++num1)
      {
        if (endian == EndianType.LittleEndian)
        {
          uint[] numArray2 = numArray1;
          int index1 = num1;
          byte[] numArray3 = array;
          int index2 = num2;
          int num3 = index2 + 1;
          int num4 = (int) numArray3[index2] & (int) byte.MaxValue;
          byte[] numArray4 = array;
          int index3 = num3;
          int num5 = index3 + 1;
          int num6 = ((int) numArray4[index3] & (int) byte.MaxValue) << 8;
          int num7 = num4 | num6;
          byte[] numArray5 = array;
          int index4 = num5;
          int num8 = index4 + 1;
          int num9 = ((int) numArray5[index4] & (int) byte.MaxValue) << 16;
          int num10 = num7 | num9;
          byte[] numArray6 = array;
          int index5 = num8;
          num2 = index5 + 1;
          int num11 = ((int) numArray6[index5] & (int) byte.MaxValue) << 24;
          int num12 = num10 | num11;
          numArray2[index1] = (uint) num12;
        }
        else
        {
          uint[] numArray2 = numArray1;
          int index1 = num1;
          byte[] numArray3 = array;
          int index2 = num2;
          int num3 = index2 + 1;
          int num4 = ((int) numArray3[index2] & (int) byte.MaxValue) << 24;
          byte[] numArray4 = array;
          int index3 = num3;
          int num5 = index3 + 1;
          int num6 = ((int) numArray4[index3] & (int) byte.MaxValue) << 16;
          int num7 = num4 | num6;
          byte[] numArray5 = array;
          int index4 = num5;
          int num8 = index4 + 1;
          int num9 = ((int) numArray5[index4] & (int) byte.MaxValue) << 8;
          int num10 = num7 | num9;
          byte[] numArray6 = array;
          int index5 = num8;
          num2 = index5 + 1;
          int num11 = (int) numArray6[index5] & (int) byte.MaxValue;
          int num12 = num10 | num11;
          numArray2[index1] = (uint) num12;
        }
      }
      return numArray1;
    }

    [CLSCompliant(false)]
    public static byte[] ULongToByte(ulong data)
    {
      return Utilities.ULongToByte(new ulong[1]
      {
        data
      }, 0, 1, EndianType.LittleEndian);
    }

    [CLSCompliant(false)]
    public static byte[] ULongToByte(ulong[] array)
    {
      return Utilities.ULongToByte(array, 0, array.Length, EndianType.LittleEndian);
    }

    [CLSCompliant(false)]
    public static byte[] ULongToByte(ulong data, EndianType endian)
    {
      return Utilities.ULongToByte(new ulong[1]
      {
        data
      }, 0, 1, endian);
    }

    [CLSCompliant(false)]
    public static byte[] ULongToByte(ulong[] array, EndianType endian)
    {
      return Utilities.ULongToByte(array, 0, array.Length, endian);
    }

    [CLSCompliant(false)]
    public static byte[] ULongToByte(ulong[] array, int offset, int length)
    {
      return Utilities.ULongToByte(array, offset, length, EndianType.LittleEndian);
    }

    [CLSCompliant(false)]
    public static byte[] ULongToByte(ulong[] array, int offset, int length, EndianType endian)
    {
      if (length + offset > array.Length)
        throw new Exception("The length and offset provided extend past the end of the array.");
      byte[] numArray = new byte[length * 8];
      for (int index1 = offset; index1 < offset + length; ++index1)
      {
        for (int index2 = 0; index2 < 8; ++index2)
        {
          if (endian == EndianType.LittleEndian)
            numArray[(index1 - offset) * 8 + index2] = (byte) (array[index1] >> index2 * 8);
          else
            numArray[(index1 - offset) * 8 + (7 - index2)] = (byte) (array[index1] >> index2 * 8);
        }
      }
      return numArray;
    }

    public static byte[] UShortToByte(ushort[] array)
    {
      return Utilities.UShortToByte(array, 0, array.Length, EndianType.LittleEndian);
    }

    public static byte[] UShortToByte(ushort data)
    {
      return Utilities.UShortToByte(new ushort[1]
      {
        data
      }, 0, 1, EndianType.LittleEndian);
    }

    public static byte[] UShortToByte(ushort data, EndianType endian)
    {
      return Utilities.UShortToByte(new ushort[1]
      {
        data
      }, 0, 1, endian);
    }

    public static byte[] UShortToByte(ushort[] array, EndianType endian)
    {
      return Utilities.UShortToByte(array, 0, array.Length, endian);
    }

    public static byte[] UShortToByte(ushort[] array, int offset, int length)
    {
      return Utilities.UShortToByte(array, offset, length, EndianType.LittleEndian);
    }

    public static byte[] UShortToByte(ushort[] array, int offset, int length, EndianType endian)
    {
      byte[] numArray = new byte[length * 2];
      for (int index1 = offset; index1 < offset + length; ++index1)
      {
        for (int index2 = 0; index2 < 2; ++index2)
        {
          if (endian == EndianType.LittleEndian)
            numArray[(index1 - offset) * 2 + index2] = (byte) ((uint) array[index1] >> index2 * 8);
          else
            numArray[(index1 - offset) * 2 + (1 - index2)] = (byte) ((uint) array[index1] >> index2 * 8);
        }
      }
      return numArray;
    }

    public static byte[] UIntToByte(uint data)
    {
      return Utilities.UIntToByte(new uint[1]
      {
        data
      }, 0, 1, EndianType.LittleEndian);
    }

    public static byte[] UIntToByte(uint[] array)
    {
      return Utilities.UIntToByte(array, 0, array.Length, EndianType.LittleEndian);
    }

    public static byte[] UIntToByte(uint[] array, EndianType endian)
    {
      return Utilities.UIntToByte(array, 0, array.Length, endian);
    }

    public static byte[] UIntToByte(uint data, EndianType endian)
    {
      return Utilities.UIntToByte(new uint[1]
      {
        data
      }, 0, 1, endian);
    }

    public static byte[] UIntToByte(uint[] array, int offset, int length)
    {
      return Utilities.UIntToByte(array, offset, length, EndianType.LittleEndian);
    }

    public static byte[] UIntToByte(uint[] array, int offset, int length, EndianType endian)
    {
      if (length + offset > array.Length)
        throw new Exception("The length and offset provided extend past the end of the array.");
      byte[] numArray = new byte[length * 4];
      for (int index1 = offset; index1 < offset + length; ++index1)
      {
        for (int index2 = 0; index2 < 4; ++index2)
        {
          if (endian == EndianType.LittleEndian)
            numArray[(index1 - offset) * 4 + index2] = (byte) (array[index1] >> index2 * 8);
          else
            numArray[(index1 - offset) * 4 + (3 - index2)] = (byte) (array[index1] >> index2 * 8);
        }
      }
      return numArray;
    }

    [CLSCompliant(false)]
    public static ushort RotateRight(ushort x, int shift)
    {
      return (ushort) ((int) x >> shift | (int) x << 16 - shift);
    }

    [CLSCompliant(false)]
    public static uint RotateRight(uint x, int shift)
    {
      return x >> shift | x << 32 - shift;
    }

    [CLSCompliant(false)]
    public static ulong RotateRight(ulong x, int shift)
    {
      return x >> shift | x << 64 - shift;
    }

    public static ushort RotateLeft(ushort x, int shift)
    {
      return (ushort) ((int) x << shift | (int) x >> 16 - shift);
    }

    [CLSCompliant(false)]
    public static uint RotateLeft(uint x, int shift)
    {
      return x << shift | x >> 32 - shift;
    }

    [CLSCompliant(false)]
    public static ulong RotateLeft(ulong x, int shift)
    {
      return x << shift | x >> 64 - shift;
    }
  }
}
