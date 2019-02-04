using System;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class GOSTHash : BlockHashAlgorithm
  {
    private static uint[] SBox1 = new uint[256];
    private static uint[] SBox2 = new uint[256];
    private static uint[] SBox3 = new uint[256];
    private static uint[] SBox4 = new uint[256];
    private uint[] accumulator;
    private uint[] sum;

    public override int HashSize
    {
      get
      {
        return 256;
      }
    }

    public GOSTHash()
      : base(32)
    {
      lock (this)
        this.Initialize();
    }

    static GOSTHash()
    {
      uint[,] numArray = new uint[8, 16]
      {
        {
          4U,
          10U,
          9U,
          2U,
          13U,
          8U,
          0U,
          14U,
          6U,
          11U,
          1U,
          12U,
          7U,
          15U,
          5U,
          3U
        },
        {
          14U,
          11U,
          4U,
          12U,
          6U,
          13U,
          15U,
          10U,
          2U,
          3U,
          8U,
          1U,
          0U,
          7U,
          5U,
          9U
        },
        {
          5U,
          8U,
          1U,
          13U,
          10U,
          3U,
          4U,
          2U,
          14U,
          15U,
          12U,
          7U,
          6U,
          0U,
          9U,
          11U
        },
        {
          7U,
          13U,
          10U,
          1U,
          0U,
          8U,
          9U,
          15U,
          14U,
          4U,
          6U,
          12U,
          11U,
          2U,
          5U,
          3U
        },
        {
          6U,
          12U,
          7U,
          1U,
          5U,
          15U,
          13U,
          8U,
          4U,
          10U,
          9U,
          14U,
          0U,
          3U,
          11U,
          2U
        },
        {
          4U,
          11U,
          10U,
          0U,
          7U,
          2U,
          1U,
          13U,
          3U,
          6U,
          8U,
          5U,
          9U,
          12U,
          15U,
          14U
        },
        {
          13U,
          11U,
          4U,
          1U,
          3U,
          15U,
          5U,
          9U,
          0U,
          10U,
          14U,
          7U,
          6U,
          8U,
          2U,
          12U
        },
        {
          1U,
          15U,
          13U,
          0U,
          5U,
          7U,
          10U,
          4U,
          9U,
          2U,
          3U,
          14U,
          6U,
          11U,
          8U,
          12U
        }
      };
      int index1 = 0;
      int index2 = 0;
      for (; index1 < 16; ++index1)
      {
        uint num1 = numArray[1, index1] << 15;
        uint num2 = numArray[3, index1] << 23;
        uint num3 = numArray[5, index1];
        uint num4 = num3 >> 1 | num3 << 31;
        uint num5 = numArray[7, index1] << 7;
        for (int index3 = 0; index3 < 16; ++index3)
        {
          GOSTHash.SBox1[index2] = num1 | numArray[0, index3] << 11;
          GOSTHash.SBox2[index2] = num2 | numArray[2, index3] << 19;
          GOSTHash.SBox3[index2] = num4 | numArray[4, index3] << 27;
          GOSTHash.SBox4[index2++] = num5 | numArray[6, index3] << 3;
        }
      }
    }

    public override void Initialize()
    {
      lock (this)
      {
        this.accumulator = new uint[8];
        this.sum = new uint[8];
        base.Initialize();
      }
    }

    protected override void ProcessBlock(byte[] inputBuffer, int inputOffset)
    {
      lock (this)
      {
        bool flag = false;
        uint[] m = Utilities.ByteToUInt(inputBuffer, inputOffset, this.BlockSize);
        for (int index = 0; index < 8; ++index)
        {
          if (flag)
          {
            this.sum[index] += m[index] + 1U;
            flag = this.sum[index] <= m[index];
          }
          else
          {
            this.sum[index] += m[index];
            flag = this.sum[index] < m[index];
          }
        }
        this.Compress(m);
      }
    }

    protected override byte[] ProcessFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
      lock (this)
      {
        uint[] m = new uint[8];
        if (inputCount > 0)
        {
          for (int index = inputOffset + inputCount; index < inputBuffer.Length; ++index)
            inputBuffer[index] = (byte) 0;
          this.ProcessBlock(inputBuffer, inputOffset);
        }
        ulong num = ((ulong) this.Count + (ulong) inputCount) * 8UL;
        m[0] = (uint) (num & (ulong) uint.MaxValue);
        m[1] = (uint) (num >> 32 & (ulong) uint.MaxValue);
        this.Compress(m);
        this.Compress(this.sum);
        return Utilities.UIntToByte(this.accumulator);
      }
    }

    private void Compress(uint[] m)
    {
      uint[] numArray1 = new uint[8];
      uint[] numArray2 = new uint[8];
      uint[] numArray3 = new uint[8];
      uint[] numArray4 = new uint[8];
      uint[] numArray5 = new uint[8];
      Array.Copy((Array) this.accumulator, 0, (Array) numArray2, 0, 8);
      Array.Copy((Array) m, 0, (Array) numArray3, 0, 8);
      int index = 0;
      while (index < 8)
      {
        numArray4[0] = numArray2[0] ^ numArray3[0];
        numArray4[1] = numArray2[1] ^ numArray3[1];
        numArray4[2] = numArray2[2] ^ numArray3[2];
        numArray4[3] = numArray2[3] ^ numArray3[3];
        numArray4[4] = numArray2[4] ^ numArray3[4];
        numArray4[5] = numArray2[5] ^ numArray3[5];
        numArray4[6] = numArray2[6] ^ numArray3[6];
        numArray4[7] = numArray2[7] ^ numArray3[7];
        numArray1[0] = (uint) ((int) numArray4[0] & (int) byte.MaxValue | ((int) numArray4[2] & (int) byte.MaxValue) << 8 | ((int) numArray4[4] & (int) byte.MaxValue) << 16 | ((int) numArray4[6] & (int) byte.MaxValue) << 24);
        numArray1[1] = (uint) ((int) ((numArray4[0] & 65280U) >> 8) | (int) numArray4[2] & 65280 | ((int) numArray4[4] & 65280) << 8 | ((int) numArray4[6] & 65280) << 16);
        numArray1[2] = (uint) ((int) ((numArray4[0] & 16711680U) >> 16) | (int) ((numArray4[2] & 16711680U) >> 8) | (int) numArray4[4] & 16711680 | ((int) numArray4[6] & 16711680) << 8);
        numArray1[3] = (uint) ((int) ((numArray4[0] & 4278190080U) >> 24) | (int) ((numArray4[2] & 4278190080U) >> 16) | (int) ((numArray4[4] & 4278190080U) >> 8) | (int) numArray4[6] & -16777216);
        numArray1[4] = (uint) ((int) numArray4[1] & (int) byte.MaxValue | ((int) numArray4[3] & (int) byte.MaxValue) << 8 | ((int) numArray4[5] & (int) byte.MaxValue) << 16 | ((int) numArray4[7] & (int) byte.MaxValue) << 24);
        numArray1[5] = (uint) ((int) ((numArray4[1] & 65280U) >> 8) | (int) numArray4[3] & 65280 | ((int) numArray4[5] & 65280) << 8 | ((int) numArray4[7] & 65280) << 16);
        numArray1[6] = (uint) ((int) ((numArray4[1] & 16711680U) >> 16) | (int) ((numArray4[3] & 16711680U) >> 8) | (int) numArray4[5] & 16711680 | ((int) numArray4[7] & 16711680) << 8);
        numArray1[7] = (uint) ((int) ((numArray4[1] & 4278190080U) >> 24) | (int) ((numArray4[3] & 4278190080U) >> 16) | (int) ((numArray4[5] & 4278190080U) >> 8) | (int) numArray4[7] & -16777216);
        uint num1 = this.accumulator[index];
        uint num2 = this.accumulator[index + 1];
        uint num3 = numArray1[0] + num1;
        uint num4 = num2 ^ (GOSTHash.SBox1[(int) num3 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num3 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num3 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num3 >> 24)]);
        uint num5 = numArray1[1] + num4;
        uint num6 = num1 ^ (GOSTHash.SBox1[(int) num5 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num5 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num5 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num5 >> 24)]);
        uint num7 = numArray1[2] + num6;
        uint num8 = num4 ^ (GOSTHash.SBox1[(int) num7 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num7 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num7 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num7 >> 24)]);
        uint num9 = numArray1[3] + num8;
        uint num10 = num6 ^ (GOSTHash.SBox1[(int) num9 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num9 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num9 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num9 >> 24)]);
        uint num11 = numArray1[4] + num10;
        uint num12 = num8 ^ (GOSTHash.SBox1[(int) num11 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num11 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num11 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num11 >> 24)]);
        uint num13 = numArray1[5] + num12;
        uint num14 = num10 ^ (GOSTHash.SBox1[(int) num13 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num13 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num13 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num13 >> 24)]);
        uint num15 = numArray1[6] + num14;
        uint num16 = num12 ^ (GOSTHash.SBox1[(int) num15 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num15 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num15 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num15 >> 24)]);
        uint num17 = numArray1[7] + num16;
        uint num18 = num14 ^ (GOSTHash.SBox1[(int) num17 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num17 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num17 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num17 >> 24)]);
        uint num19 = numArray1[0] + num18;
        uint num20 = num16 ^ (GOSTHash.SBox1[(int) num19 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num19 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num19 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num19 >> 24)]);
        uint num21 = numArray1[1] + num20;
        uint num22 = num18 ^ (GOSTHash.SBox1[(int) num21 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num21 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num21 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num21 >> 24)]);
        uint num23 = numArray1[2] + num22;
        uint num24 = num20 ^ (GOSTHash.SBox1[(int) num23 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num23 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num23 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num23 >> 24)]);
        uint num25 = numArray1[3] + num24;
        uint num26 = num22 ^ (GOSTHash.SBox1[(int) num25 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num25 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num25 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num25 >> 24)]);
        uint num27 = numArray1[4] + num26;
        uint num28 = num24 ^ (GOSTHash.SBox1[(int) num27 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num27 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num27 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num27 >> 24)]);
        uint num29 = numArray1[5] + num28;
        uint num30 = num26 ^ (GOSTHash.SBox1[(int) num29 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num29 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num29 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num29 >> 24)]);
        uint num31 = numArray1[6] + num30;
        uint num32 = num28 ^ (GOSTHash.SBox1[(int) num31 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num31 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num31 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num31 >> 24)]);
        uint num33 = numArray1[7] + num32;
        uint num34 = num30 ^ (GOSTHash.SBox1[(int) num33 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num33 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num33 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num33 >> 24)]);
        uint num35 = numArray1[0] + num34;
        uint num36 = num32 ^ (GOSTHash.SBox1[(int) num35 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num35 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num35 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num35 >> 24)]);
        uint num37 = numArray1[1] + num36;
        uint num38 = num34 ^ (GOSTHash.SBox1[(int) num37 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num37 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num37 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num37 >> 24)]);
        uint num39 = numArray1[2] + num38;
        uint num40 = num36 ^ (GOSTHash.SBox1[(int) num39 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num39 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num39 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num39 >> 24)]);
        uint num41 = numArray1[3] + num40;
        uint num42 = num38 ^ (GOSTHash.SBox1[(int) num41 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num41 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num41 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num41 >> 24)]);
        uint num43 = numArray1[4] + num42;
        uint num44 = num40 ^ (GOSTHash.SBox1[(int) num43 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num43 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num43 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num43 >> 24)]);
        uint num45 = numArray1[5] + num44;
        uint num46 = num42 ^ (GOSTHash.SBox1[(int) num45 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num45 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num45 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num45 >> 24)]);
        uint num47 = numArray1[6] + num46;
        uint num48 = num44 ^ (GOSTHash.SBox1[(int) num47 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num47 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num47 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num47 >> 24)]);
        uint num49 = numArray1[7] + num48;
        uint num50 = num46 ^ (GOSTHash.SBox1[(int) num49 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num49 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num49 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num49 >> 24)]);
        uint num51 = numArray1[7] + num50;
        uint num52 = num48 ^ (GOSTHash.SBox1[(int) num51 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num51 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num51 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num51 >> 24)]);
        uint num53 = numArray1[6] + num52;
        uint num54 = num50 ^ (GOSTHash.SBox1[(int) num53 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num53 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num53 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num53 >> 24)]);
        uint num55 = numArray1[5] + num54;
        uint num56 = num52 ^ (GOSTHash.SBox1[(int) num55 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num55 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num55 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num55 >> 24)]);
        uint num57 = numArray1[4] + num56;
        uint num58 = num54 ^ (GOSTHash.SBox1[(int) num57 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num57 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num57 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num57 >> 24)]);
        uint num59 = numArray1[3] + num58;
        uint num60 = num56 ^ (GOSTHash.SBox1[(int) num59 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num59 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num59 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num59 >> 24)]);
        uint num61 = numArray1[2] + num60;
        uint num62 = num58 ^ (GOSTHash.SBox1[(int) num61 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num61 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num61 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num61 >> 24)]);
        uint num63 = numArray1[1] + num62;
        uint num64 = num60 ^ (GOSTHash.SBox1[(int) num63 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num63 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num63 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num63 >> 24)]);
        uint num65 = numArray1[0] + num64;
        uint num66 = num62 ^ (GOSTHash.SBox1[(int) num65 & (int) byte.MaxValue] ^ GOSTHash.SBox2[(int) (num65 >> 8) & (int) byte.MaxValue] ^ GOSTHash.SBox3[(int) (num65 >> 16) & (int) byte.MaxValue] ^ GOSTHash.SBox4[(int) (num65 >> 24)]);
        uint num67 = num64;
        uint num68 = num66;
        numArray5[index] = num67;
        numArray5[index + 1] = num68;
        if (index != 6)
        {
          uint num69 = numArray2[0] ^ numArray2[2];
          uint num70 = numArray2[1] ^ numArray2[3];
          numArray2[0] = numArray2[2];
          numArray2[1] = numArray2[3];
          numArray2[2] = numArray2[4];
          numArray2[3] = numArray2[5];
          numArray2[4] = numArray2[6];
          numArray2[5] = numArray2[7];
          numArray2[6] = num69;
          numArray2[7] = num70;
          if (index == 2)
          {
            numArray2[0] ^= 4278255360U;
            numArray2[1] ^= 4278255360U;
            numArray2[2] ^= 16711935U;
            numArray2[3] ^= 16711935U;
            numArray2[4] ^= 16776960U;
            numArray2[5] ^= 4278190335U;
            numArray2[6] ^= (uint) byte.MaxValue;
            numArray2[7] ^= 4278255615U;
          }
          uint num71 = numArray3[0];
          uint num72 = numArray3[2];
          numArray3[0] = numArray3[4];
          numArray3[2] = numArray3[6];
          numArray3[4] = num71 ^ num72;
          numArray3[6] = numArray3[0] ^ num72;
          uint num73 = numArray3[1];
          uint num74 = numArray3[3];
          numArray3[1] = numArray3[5];
          numArray3[3] = numArray3[7];
          numArray3[5] = num73 ^ num74;
          numArray3[7] = numArray3[1] ^ num74;
          index += 2;
        }
        else
          break;
      }
      numArray2[0] = m[0] ^ numArray5[6];
      numArray2[1] = m[1] ^ numArray5[7];
      numArray2[2] = (uint) ((int) m[2] ^ (int) numArray5[0] << 16 ^ (int) (numArray5[0] >> 16) ^ (int) numArray5[0] & (int) ushort.MaxValue ^ (int) numArray5[1] & (int) ushort.MaxValue ^ (int) (numArray5[1] >> 16) ^ (int) numArray5[2] << 16 ^ (int) numArray5[6] ^ (int) numArray5[6] << 16 ^ (int) numArray5[7] & -65536) ^ numArray5[7] >> 16;
      numArray2[3] = (uint) ((int) m[3] ^ (int) numArray5[0] & (int) ushort.MaxValue ^ (int) numArray5[0] << 16 ^ (int) numArray5[1] & (int) ushort.MaxValue ^ (int) numArray5[1] << 16 ^ (int) (numArray5[1] >> 16) ^ (int) numArray5[2] << 16 ^ (int) (numArray5[2] >> 16) ^ (int) numArray5[3] << 16 ^ (int) numArray5[6] ^ (int) numArray5[6] << 16 ^ (int) (numArray5[6] >> 16) ^ (int) numArray5[7] & (int) ushort.MaxValue ^ (int) numArray5[7] << 16) ^ numArray5[7] >> 16;
      numArray2[4] = (uint) ((int) m[4] ^ (int) numArray5[0] & -65536 ^ (int) numArray5[0] << 16 ^ (int) (numArray5[0] >> 16) ^ (int) numArray5[1] & -65536 ^ (int) (numArray5[1] >> 16) ^ (int) numArray5[2] << 16 ^ (int) (numArray5[2] >> 16) ^ (int) numArray5[3] << 16 ^ (int) (numArray5[3] >> 16) ^ (int) numArray5[4] << 16 ^ (int) numArray5[6] << 16 ^ (int) (numArray5[6] >> 16) ^ (int) numArray5[7] & (int) ushort.MaxValue ^ (int) numArray5[7] << 16) ^ numArray5[7] >> 16;
      numArray2[5] = (uint) ((int) m[5] ^ (int) numArray5[0] << 16 ^ (int) (numArray5[0] >> 16) ^ (int) numArray5[0] & -65536 ^ (int) numArray5[1] & (int) ushort.MaxValue ^ (int) numArray5[2] ^ (int) (numArray5[2] >> 16) ^ (int) numArray5[3] << 16 ^ (int) (numArray5[3] >> 16) ^ (int) numArray5[4] << 16 ^ (int) (numArray5[4] >> 16) ^ (int) numArray5[5] << 16 ^ (int) numArray5[6] << 16 ^ (int) (numArray5[6] >> 16) ^ (int) numArray5[7] & -65536 ^ (int) numArray5[7] << 16) ^ numArray5[7] >> 16;
      numArray2[6] = (uint) ((int) m[6] ^ (int) numArray5[0] ^ (int) (numArray5[1] >> 16) ^ (int) numArray5[2] << 16 ^ (int) numArray5[3] ^ (int) (numArray5[3] >> 16) ^ (int) numArray5[4] << 16 ^ (int) (numArray5[4] >> 16) ^ (int) numArray5[5] << 16 ^ (int) (numArray5[5] >> 16) ^ (int) numArray5[6] ^ (int) numArray5[6] << 16 ^ (int) (numArray5[6] >> 16) ^ (int) numArray5[7] << 16);
      numArray2[7] = (uint) ((int) m[7] ^ (int) numArray5[0] & -65536 ^ (int) numArray5[0] << 16 ^ (int) numArray5[1] & (int) ushort.MaxValue ^ (int) numArray5[1] << 16 ^ (int) (numArray5[2] >> 16) ^ (int) numArray5[3] << 16 ^ (int) numArray5[4] ^ (int) (numArray5[4] >> 16) ^ (int) numArray5[5] << 16 ^ (int) (numArray5[5] >> 16) ^ (int) (numArray5[6] >> 16) ^ (int) numArray5[7] & (int) ushort.MaxValue ^ (int) numArray5[7] << 16) ^ numArray5[7] >> 16;
      numArray3[0] = this.accumulator[0] ^ numArray2[1] << 16 ^ numArray2[0] >> 16;
      numArray3[1] = this.accumulator[1] ^ numArray2[2] << 16 ^ numArray2[1] >> 16;
      numArray3[2] = this.accumulator[2] ^ numArray2[3] << 16 ^ numArray2[2] >> 16;
      numArray3[3] = this.accumulator[3] ^ numArray2[4] << 16 ^ numArray2[3] >> 16;
      numArray3[4] = this.accumulator[4] ^ numArray2[5] << 16 ^ numArray2[4] >> 16;
      numArray3[5] = this.accumulator[5] ^ numArray2[6] << 16 ^ numArray2[5] >> 16;
      numArray3[6] = this.accumulator[6] ^ numArray2[7] << 16 ^ numArray2[6] >> 16;
      numArray3[7] = (uint) ((int) this.accumulator[7] ^ (int) numArray2[0] & -65536 ^ (int) numArray2[0] << 16 ^ (int) (numArray2[7] >> 16) ^ (int) numArray2[1] & -65536 ^ (int) numArray2[1] << 16 ^ (int) numArray2[6] << 16 ^ (int) numArray2[7] & -65536);
      this.accumulator[0] = (uint) ((int) numArray3[0] & -65536 ^ (int) numArray3[0] << 16 ^ (int) (numArray3[0] >> 16) ^ (int) (numArray3[1] >> 16) ^ (int) numArray3[1] & -65536 ^ (int) numArray3[2] << 16 ^ (int) (numArray3[3] >> 16) ^ (int) numArray3[4] << 16 ^ (int) (numArray3[5] >> 16) ^ (int) numArray3[5] ^ (int) (numArray3[6] >> 16) ^ (int) numArray3[7] << 16 ^ (int) (numArray3[7] >> 16) ^ (int) numArray3[7] & (int) ushort.MaxValue);
      this.accumulator[1] = (uint) ((int) numArray3[0] << 16 ^ (int) (numArray3[0] >> 16) ^ (int) numArray3[0] & -65536 ^ (int) numArray3[1] & (int) ushort.MaxValue ^ (int) numArray3[2] ^ (int) (numArray3[2] >> 16) ^ (int) numArray3[3] << 16 ^ (int) (numArray3[4] >> 16) ^ (int) numArray3[5] << 16 ^ (int) numArray3[6] << 16 ^ (int) numArray3[6] ^ (int) numArray3[7] & -65536) ^ numArray3[7] >> 16;
      this.accumulator[2] = (uint) ((int) numArray3[0] & (int) ushort.MaxValue ^ (int) numArray3[0] << 16 ^ (int) numArray3[1] << 16 ^ (int) (numArray3[1] >> 16) ^ (int) numArray3[1] & -65536 ^ (int) numArray3[2] << 16 ^ (int) (numArray3[3] >> 16) ^ (int) numArray3[3] ^ (int) numArray3[4] << 16 ^ (int) (numArray3[5] >> 16) ^ (int) numArray3[6] ^ (int) (numArray3[6] >> 16) ^ (int) numArray3[7] & (int) ushort.MaxValue ^ (int) numArray3[7] << 16) ^ numArray3[7] >> 16;
      this.accumulator[3] = (uint) ((int) numArray3[0] << 16 ^ (int) (numArray3[0] >> 16) ^ (int) numArray3[0] & -65536 ^ (int) numArray3[1] & -65536 ^ (int) (numArray3[1] >> 16) ^ (int) numArray3[2] << 16 ^ (int) (numArray3[2] >> 16) ^ (int) numArray3[2] ^ (int) numArray3[3] << 16 ^ (int) (numArray3[4] >> 16) ^ (int) numArray3[4] ^ (int) numArray3[5] << 16 ^ (int) numArray3[6] << 16 ^ (int) numArray3[7] & (int) ushort.MaxValue) ^ numArray3[7] >> 16;
      this.accumulator[4] = (uint) ((int) (numArray3[0] >> 16) ^ (int) numArray3[1] << 16 ^ (int) numArray3[1] ^ (int) (numArray3[2] >> 16) ^ (int) numArray3[2] ^ (int) numArray3[3] << 16 ^ (int) (numArray3[3] >> 16) ^ (int) numArray3[3] ^ (int) numArray3[4] << 16 ^ (int) (numArray3[5] >> 16) ^ (int) numArray3[5] ^ (int) numArray3[6] << 16 ^ (int) (numArray3[6] >> 16) ^ (int) numArray3[7] << 16);
      this.accumulator[5] = (uint) ((int) numArray3[0] << 16 ^ (int) numArray3[0] & -65536 ^ (int) numArray3[1] << 16 ^ (int) (numArray3[1] >> 16) ^ (int) numArray3[1] & -65536 ^ (int) numArray3[2] << 16 ^ (int) numArray3[2] ^ (int) (numArray3[3] >> 16) ^ (int) numArray3[3] ^ (int) numArray3[4] << 16 ^ (int) (numArray3[4] >> 16) ^ (int) numArray3[4] ^ (int) numArray3[5] << 16 ^ (int) numArray3[6] << 16 ^ (int) (numArray3[6] >> 16) ^ (int) numArray3[6] ^ (int) numArray3[7] << 16 ^ (int) (numArray3[7] >> 16) ^ (int) numArray3[7] & -65536);
      this.accumulator[6] = (uint) ((int) numArray3[0] ^ (int) numArray3[2] ^ (int) (numArray3[2] >> 16) ^ (int) numArray3[3] ^ (int) numArray3[3] << 16 ^ (int) numArray3[4] ^ (int) (numArray3[4] >> 16) ^ (int) numArray3[5] << 16 ^ (int) (numArray3[5] >> 16) ^ (int) numArray3[5] ^ (int) numArray3[6] << 16 ^ (int) (numArray3[6] >> 16) ^ (int) numArray3[6] ^ (int) numArray3[7] << 16) ^ numArray3[7];
      this.accumulator[7] = (uint) ((int) numArray3[0] ^ (int) (numArray3[0] >> 16) ^ (int) numArray3[1] << 16 ^ (int) (numArray3[1] >> 16) ^ (int) numArray3[2] << 16 ^ (int) (numArray3[3] >> 16) ^ (int) numArray3[3] ^ (int) numArray3[4] << 16 ^ (int) numArray3[4] ^ (int) (numArray3[5] >> 16) ^ (int) numArray3[5] ^ (int) numArray3[6] << 16 ^ (int) (numArray3[6] >> 16) ^ (int) numArray3[7] << 16) ^ numArray3[7];
    }
  }
}
