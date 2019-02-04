using System;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class RIPEMD320 : BlockHashAlgorithm
  {
    private static int[] R = new int[80]
    {
      0,
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      7,
      4,
      13,
      1,
      10,
      6,
      15,
      3,
      12,
      0,
      9,
      5,
      2,
      14,
      11,
      8,
      3,
      10,
      14,
      4,
      9,
      15,
      8,
      1,
      2,
      7,
      0,
      6,
      13,
      11,
      5,
      12,
      1,
      9,
      11,
      10,
      0,
      8,
      12,
      4,
      13,
      3,
      7,
      15,
      14,
      5,
      6,
      2,
      4,
      0,
      5,
      9,
      7,
      12,
      2,
      10,
      14,
      1,
      3,
      8,
      11,
      6,
      15,
      13
    };
    private static int[] Rp = new int[80]
    {
      5,
      14,
      7,
      0,
      9,
      2,
      11,
      4,
      13,
      6,
      15,
      8,
      1,
      10,
      3,
      12,
      6,
      11,
      3,
      7,
      0,
      13,
      5,
      10,
      14,
      15,
      8,
      12,
      4,
      9,
      1,
      2,
      15,
      5,
      1,
      3,
      7,
      14,
      6,
      9,
      11,
      8,
      12,
      2,
      10,
      0,
      4,
      13,
      8,
      6,
      4,
      1,
      3,
      11,
      15,
      0,
      5,
      12,
      2,
      13,
      9,
      7,
      10,
      14,
      12,
      15,
      10,
      4,
      1,
      5,
      8,
      7,
      6,
      2,
      13,
      14,
      0,
      3,
      9,
      11
    };
    private static int[] S = new int[80]
    {
      11,
      14,
      15,
      12,
      5,
      8,
      7,
      9,
      11,
      13,
      14,
      15,
      6,
      7,
      9,
      8,
      7,
      6,
      8,
      13,
      11,
      9,
      7,
      15,
      7,
      12,
      15,
      9,
      11,
      7,
      13,
      12,
      11,
      13,
      6,
      7,
      14,
      9,
      13,
      15,
      14,
      8,
      13,
      6,
      5,
      12,
      7,
      5,
      11,
      12,
      14,
      15,
      14,
      15,
      9,
      8,
      9,
      14,
      5,
      6,
      8,
      6,
      5,
      12,
      9,
      15,
      5,
      11,
      6,
      8,
      13,
      12,
      5,
      12,
      13,
      14,
      11,
      8,
      5,
      6
    };
    private static int[] Sp = new int[80]
    {
      8,
      9,
      9,
      11,
      13,
      15,
      15,
      5,
      7,
      7,
      8,
      11,
      14,
      14,
      12,
      6,
      9,
      13,
      15,
      7,
      12,
      8,
      9,
      11,
      7,
      7,
      12,
      7,
      6,
      15,
      13,
      11,
      9,
      7,
      15,
      11,
      8,
      6,
      6,
      14,
      12,
      13,
      5,
      14,
      13,
      13,
      7,
      5,
      15,
      5,
      8,
      11,
      14,
      14,
      6,
      14,
      6,
      9,
      12,
      9,
      12,
      5,
      15,
      8,
      8,
      5,
      12,
      9,
      12,
      5,
      14,
      6,
      8,
      13,
      6,
      5,
      15,
      13,
      11,
      11
    };
    private uint[] accumulator;

    public override int HashSize
    {
      get
      {
        return 320;
      }
    }

    public RIPEMD320()
      : base(64)
    {
      lock (this)
      {
        this.accumulator = new uint[10];
        this.Initialize();
      }
    }

    public override void Initialize()
    {
      lock (this)
      {
        this.accumulator[0] = 1732584193U;
        this.accumulator[1] = 4023233417U;
        this.accumulator[2] = 2562383102U;
        this.accumulator[3] = 271733878U;
        this.accumulator[4] = 3285377520U;
        this.accumulator[5] = 1985229328U;
        this.accumulator[6] = 4275878552U;
        this.accumulator[7] = 2309737967U;
        this.accumulator[8] = 19088743U;
        this.accumulator[9] = 1009589775U;
        base.Initialize();
      }
    }

    protected override void ProcessBlock(byte[] inputBuffer, int inputOffset)
    {
      lock (this)
      {
        uint[] numArray = Utilities.ByteToUInt(inputBuffer, inputOffset, this.BlockSize);
        uint num1 = this.accumulator[0];
        uint num2 = this.accumulator[1];
        uint x1 = this.accumulator[2];
        uint num3 = this.accumulator[3];
        uint num4 = this.accumulator[4];
        uint num5 = this.accumulator[5];
        uint num6 = this.accumulator[6];
        uint x2 = this.accumulator[7];
        uint num7 = this.accumulator[8];
        uint num8 = this.accumulator[9];
        for (uint index = 0; index < 16U; ++index)
        {
          int num9 = RIPEMD320.S[(int) index];
          int num10 = (int) num1 + ((int) num2 ^ (int) x1 ^ (int) num3) + (int) numArray[(int) index];
          num1 = num4;
          num4 = num3;
          num3 = x1 << 10 | x1 >> 22;
          x1 = num2;
          int shift1 = num9;
          num2 = Utilities.RotateLeft((uint) num10, shift1) + num1;
          int num11 = RIPEMD320.Sp[(int) index];
          int num12 = (int) num5 + ((int) num6 ^ ((int) x2 | ~(int) num7)) + (int) numArray[RIPEMD320.Rp[(int) index]] + 1352829926;
          num5 = num8;
          num8 = num7;
          num7 = x2 << 10 | x2 >> 22;
          x2 = num6;
          int shift2 = num11;
          num6 = Utilities.RotateLeft((uint) num12, shift2) + num5;
        }
        int num13 = (int) num2;
        uint num14 = num6;
        uint num15 = (uint) num13;
        for (uint index = 16; index < 32U; ++index)
        {
          int num9 = RIPEMD320.S[(int) index];
          int num10 = (int) num1 + ((int) num14 & (int) x1 | ~(int) num14 & (int) num3) + (int) numArray[RIPEMD320.R[(int) index]] + 1518500249;
          num1 = num4;
          num4 = num3;
          num3 = Utilities.RotateLeft(x1, 10);
          x1 = num14;
          int shift1 = num9;
          num14 = Utilities.RotateLeft((uint) num10, shift1) + num1;
          int num11 = RIPEMD320.Sp[(int) index];
          int num12 = (int) num5 + ((int) num15 & (int) num7 | (int) x2 & ~(int) num7) + (int) numArray[RIPEMD320.Rp[(int) index]] + 1548603684;
          num5 = num8;
          num8 = num7;
          num7 = Utilities.RotateLeft(x2, 10);
          x2 = num15;
          int shift2 = num11;
          num15 = Utilities.RotateLeft((uint) num12, shift2) + num5;
        }
        int num16 = (int) num3;
        uint num17 = num7;
        uint num18 = (uint) num16;
        for (uint index = 32; index < 48U; ++index)
        {
          int num9 = RIPEMD320.S[(int) index];
          int num10 = (int) num1 + (((int) num14 | ~(int) x1) ^ (int) num17) + (int) numArray[RIPEMD320.R[(int) index]] + 1859775393;
          num1 = num4;
          num4 = num17;
          num17 = Utilities.RotateLeft(x1, 10);
          x1 = num14;
          int shift1 = num9;
          num14 = Utilities.RotateLeft((uint) num10, shift1) + num1;
          int num11 = RIPEMD320.Sp[(int) index];
          int num12 = (int) num5 + (((int) num15 | ~(int) x2) ^ (int) num18) + (int) numArray[RIPEMD320.Rp[(int) index]] + 1836072691;
          num5 = num8;
          num8 = num18;
          num18 = Utilities.RotateLeft(x2, 10);
          x2 = num15;
          int shift2 = num11;
          num15 = Utilities.RotateLeft((uint) num12, shift2) + num5;
        }
        int num19 = (int) num1;
        uint num20 = num5;
        uint num21 = (uint) num19;
        for (uint index = 48; index < 64U; ++index)
        {
          int num9 = RIPEMD320.S[(int) index];
          int num10 = (int) num20 + ((int) num14 & (int) num17 | (int) x1 & ~(int) num17) + (int) numArray[RIPEMD320.R[(int) index]] - 1894007588;
          num20 = num4;
          num4 = num17;
          num17 = Utilities.RotateLeft(x1, 10);
          x1 = num14;
          int shift1 = num9;
          num14 = Utilities.RotateLeft((uint) num10, shift1) + num20;
          int num11 = RIPEMD320.Sp[(int) index];
          int num12 = (int) num21 + ((int) num15 & (int) x2 | ~(int) num15 & (int) num18) + (int) numArray[RIPEMD320.Rp[(int) index]] + 2053994217;
          num21 = num8;
          num8 = num18;
          num18 = Utilities.RotateLeft(x2, 10);
          x2 = num15;
          int shift2 = num11;
          num15 = Utilities.RotateLeft((uint) num12, shift2) + num21;
        }
        int num22 = (int) x1;
        uint x3 = x2;
        uint x4 = (uint) num22;
        for (uint index = 64; index < 80U; ++index)
        {
          int num9 = RIPEMD320.S[(int) index];
          int num10 = (int) num20 + ((int) num14 ^ ((int) x3 | ~(int) num17)) + (int) numArray[RIPEMD320.R[(int) index]] - 1454113458;
          num20 = num4;
          num4 = num17;
          num17 = Utilities.RotateLeft(x3, 10);
          x3 = num14;
          int shift1 = num9;
          num14 = Utilities.RotateLeft((uint) num10, shift1) + num20;
          int num11 = RIPEMD320.Sp[(int) index];
          int num12 = (int) num21 + ((int) num15 ^ (int) x4 ^ (int) num18) + (int) numArray[RIPEMD320.Rp[(int) index]];
          num21 = num8;
          num8 = num18;
          num18 = Utilities.RotateLeft(x4, 10);
          x4 = num15;
          int shift2 = num11;
          num15 = Utilities.RotateLeft((uint) num12, shift2) + num21;
        }
        int num23 = (int) num4;
        uint num24 = num8;
        uint num25 = (uint) num23;
        this.accumulator[0] += num20;
        this.accumulator[1] += num14;
        this.accumulator[2] += x3;
        this.accumulator[3] += num17;
        this.accumulator[4] += num24;
        this.accumulator[5] += num21;
        this.accumulator[6] += num15;
        this.accumulator[7] += x4;
        this.accumulator[8] += num18;
        this.accumulator[9] += num25;
      }
    }

    protected override byte[] ProcessFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
      lock (this)
      {
        int num = this.BlockSize - 8 - (int) (((ulong) inputCount + (ulong) this.Count) % (ulong) this.BlockSize);
        if (num < 1)
          num += this.BlockSize;
        byte[] inputBuffer1 = new byte[inputCount + num + 8];
        Array.Copy((Array) inputBuffer, inputOffset, (Array) inputBuffer1, 0, inputCount);
        inputBuffer1[inputCount] = (byte) 128;
        Array.Copy((Array) Utilities.ULongToByte(((ulong) this.Count + (ulong) inputCount) * 8UL), 0, (Array) inputBuffer1, inputCount + num, 8);
        this.ProcessBlock(inputBuffer1, 0);
        if (inputBuffer1.Length == this.BlockSize * 2)
          this.ProcessBlock(inputBuffer1, this.BlockSize);
        return Utilities.UIntToByte(this.accumulator);
      }
    }
  }
}
