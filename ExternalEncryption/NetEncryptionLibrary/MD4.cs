using System;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class MD4 : BlockHashAlgorithm
  {
    internal uint[] accumulator;

    public override int HashSize
    {
      get
      {
        return 128;
      }
    }

    public MD4()
      : base(64)
    {
      lock (this)
      {
        this.accumulator = new uint[4];
        this.Initialize();
      }
    }

    private uint FF(uint a, uint b, uint c, uint d, uint x, int s)
    {
      return Utilities.RotateLeft(a + (uint) ((int) b & (int) c | ~(int) b & (int) d) + x, s);
    }

    private uint GG(uint a, uint b, uint c, uint d, uint x, int s)
    {
      return Utilities.RotateLeft((uint) ((int) a + ((int) b & (int) c | (int) b & (int) d | (int) c & (int) d) + (int) x + 1518500249), s);
    }

    private uint HH(uint a, uint b, uint c, uint d, uint x, int s)
    {
      return Utilities.RotateLeft((uint) ((int) a + ((int) b ^ (int) c ^ (int) d) + (int) x + 1859775393), s);
    }

    public override void Initialize()
    {
      lock (this)
      {
        this.accumulator[0] = 1732584193U;
        this.accumulator[1] = 4023233417U;
        this.accumulator[2] = 2562383102U;
        this.accumulator[3] = 271733878U;
        base.Initialize();
      }
    }

    protected override void ProcessBlock(byte[] inputBuffer, int inputOffset)
    {
      lock (this)
      {
        uint a = this.accumulator[0];
        uint num1 = this.accumulator[1];
        uint num2 = this.accumulator[2];
        uint num3 = this.accumulator[3];
        uint[] numArray = Utilities.ByteToUInt(inputBuffer, inputOffset, this.BlockSize);
        uint num4 = this.FF(a, num1, num2, num3, numArray[0], 3);
        uint num5 = this.FF(num3, num4, num1, num2, numArray[1], 7);
        uint num6 = this.FF(num2, num5, num4, num1, numArray[2], 11);
        uint num7 = this.FF(num1, num6, num5, num4, numArray[3], 19);
        uint num8 = this.FF(num4, num7, num6, num5, numArray[4], 3);
        uint num9 = this.FF(num5, num8, num7, num6, numArray[5], 7);
        uint num10 = this.FF(num6, num9, num8, num7, numArray[6], 11);
        uint num11 = this.FF(num7, num10, num9, num8, numArray[7], 19);
        uint num12 = this.FF(num8, num11, num10, num9, numArray[8], 3);
        uint num13 = this.FF(num9, num12, num11, num10, numArray[9], 7);
        uint num14 = this.FF(num10, num13, num12, num11, numArray[10], 11);
        uint num15 = this.FF(num11, num14, num13, num12, numArray[11], 19);
        uint num16 = this.FF(num12, num15, num14, num13, numArray[12], 3);
        uint num17 = this.FF(num13, num16, num15, num14, numArray[13], 7);
        uint num18 = this.FF(num14, num17, num16, num15, numArray[14], 11);
        uint num19 = this.FF(num15, num18, num17, num16, numArray[15], 19);
        uint num20 = this.GG(num16, num19, num18, num17, numArray[0], 3);
        uint num21 = this.GG(num17, num20, num19, num18, numArray[4], 5);
        uint num22 = this.GG(num18, num21, num20, num19, numArray[8], 9);
        uint num23 = this.GG(num19, num22, num21, num20, numArray[12], 13);
        uint num24 = this.GG(num20, num23, num22, num21, numArray[1], 3);
        uint num25 = this.GG(num21, num24, num23, num22, numArray[5], 5);
        uint num26 = this.GG(num22, num25, num24, num23, numArray[9], 9);
        uint num27 = this.GG(num23, num26, num25, num24, numArray[13], 13);
        uint num28 = this.GG(num24, num27, num26, num25, numArray[2], 3);
        uint num29 = this.GG(num25, num28, num27, num26, numArray[6], 5);
        uint num30 = this.GG(num26, num29, num28, num27, numArray[10], 9);
        uint num31 = this.GG(num27, num30, num29, num28, numArray[14], 13);
        uint num32 = this.GG(num28, num31, num30, num29, numArray[3], 3);
        uint num33 = this.GG(num29, num32, num31, num30, numArray[7], 5);
        uint num34 = this.GG(num30, num33, num32, num31, numArray[11], 9);
        uint num35 = this.GG(num31, num34, num33, num32, numArray[15], 13);
        uint num36 = this.HH(num32, num35, num34, num33, numArray[0], 3);
        uint num37 = this.HH(num33, num36, num35, num34, numArray[8], 9);
        uint num38 = this.HH(num34, num37, num36, num35, numArray[4], 11);
        uint num39 = this.HH(num35, num38, num37, num36, numArray[12], 15);
        uint num40 = this.HH(num36, num39, num38, num37, numArray[2], 3);
        uint num41 = this.HH(num37, num40, num39, num38, numArray[10], 9);
        uint num42 = this.HH(num38, num41, num40, num39, numArray[6], 11);
        uint num43 = this.HH(num39, num42, num41, num40, numArray[14], 15);
        uint num44 = this.HH(num40, num43, num42, num41, numArray[1], 3);
        uint num45 = this.HH(num41, num44, num43, num42, numArray[9], 9);
        uint num46 = this.HH(num42, num45, num44, num43, numArray[5], 11);
        uint num47 = this.HH(num43, num46, num45, num44, numArray[13], 15);
        uint num48 = this.HH(num44, num47, num46, num45, numArray[3], 3);
        uint num49 = this.HH(num45, num48, num47, num46, numArray[11], 9);
        uint b = this.HH(num46, num49, num48, num47, numArray[7], 11);
        uint num50 = this.HH(num47, b, num49, num48, numArray[15], 15);
        this.accumulator[0] += num48;
        this.accumulator[1] += num50;
        this.accumulator[2] += b;
        this.accumulator[3] += num49;
      }
    }

    protected override byte[] ProcessFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
      lock (this)
      {
        int num = this.BlockSize - 8 - (int) (((long) inputCount + this.Count) % (long) this.BlockSize);
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
