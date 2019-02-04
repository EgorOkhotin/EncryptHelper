using System;
using System.Security.Cryptography;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class TwofishBase
  {
    private static readonly int BLOCK_SIZE = 128;
    private static readonly int MAX_ROUNDS = 16;
    private static readonly int ROUNDS_128 = 16;
    private static readonly int ROUNDS_192 = 16;
    private static readonly int ROUNDS_256 = 16;
    private static readonly int MAX_KEY_BITS = 256;
    private static readonly int INPUT_WHITEN = 0;
    private static readonly int OUTPUT_WHITEN = TwofishBase.INPUT_WHITEN + TwofishBase.BLOCK_SIZE / 32;
    private static readonly int ROUND_SUBKEYS = TwofishBase.OUTPUT_WHITEN + TwofishBase.BLOCK_SIZE / 32;
    private static readonly int TOTAL_SUBKEYS = TwofishBase.ROUND_SUBKEYS + 2 * TwofishBase.MAX_ROUNDS;
    private static readonly uint SK_STEP = 33686018;
    private static readonly uint SK_BUMP = 16843009;
    private static readonly int SK_ROTL = 9;
    private static readonly uint RS_GF_FDBK = 333;
    private static readonly int MDS_GF_FDBK = 361;
    private static readonly int P_00 = 1;
    private static readonly int P_01 = 0;
    private static readonly int P_02 = 0;
    private static readonly int P_03 = TwofishBase.P_01 ^ 1;
    private static readonly int P_04 = 1;
    private static readonly int P_10 = 0;
    private static readonly int P_11 = 0;
    private static readonly int P_12 = 1;
    private static readonly int P_13 = TwofishBase.P_11 ^ 1;
    private static readonly int P_14 = 0;
    private static readonly int P_20 = 1;
    private static readonly int P_21 = 1;
    private static readonly int P_22 = 0;
    private static readonly int P_23 = TwofishBase.P_21 ^ 1;
    private static readonly int P_24 = 0;
    private static readonly int P_30 = 0;
    private static readonly int P_31 = 1;
    private static readonly int P_32 = 1;
    private static readonly int P_33 = TwofishBase.P_31 ^ 1;
    private static readonly int P_34 = 1;
    private static byte[,] P8x8 = new byte[2, 256]
    {
      {
        (byte) 169,
        (byte) 103,
        (byte) 179,
        (byte) 232,
        (byte) 4,
        (byte) 253,
        (byte) 163,
        (byte) 118,
        (byte) 154,
        (byte) 146,
        (byte) 128,
        (byte) 120,
        (byte) 228,
        (byte) 221,
        (byte) 209,
        (byte) 56,
        (byte) 13,
        (byte) 198,
        (byte) 53,
        (byte) 152,
        (byte) 24,
        (byte) 247,
        (byte) 236,
        (byte) 108,
        (byte) 67,
        (byte) 117,
        (byte) 55,
        (byte) 38,
        (byte) 250,
        (byte) 19,
        (byte) 148,
        (byte) 72,
        (byte) 242,
        (byte) 208,
        (byte) 139,
        (byte) 48,
        (byte) 132,
        (byte) 84,
        (byte) 223,
        (byte) 35,
        (byte) 25,
        (byte) 91,
        (byte) 61,
        (byte) 89,
        (byte) 243,
        (byte) 174,
        (byte) 162,
        (byte) 130,
        (byte) 99,
        (byte) 1,
        (byte) 131,
        (byte) 46,
        (byte) 217,
        (byte) 81,
        (byte) 155,
        (byte) 124,
        (byte) 166,
        (byte) 235,
        (byte) 165,
        (byte) 190,
        (byte) 22,
        (byte) 12,
        (byte) 227,
        (byte) 97,
        (byte) 192,
        (byte) 140,
        (byte) 58,
        (byte) 245,
        (byte) 115,
        (byte) 44,
        (byte) 37,
        (byte) 11,
        (byte) 187,
        (byte) 78,
        (byte) 137,
        (byte) 107,
        (byte) 83,
        (byte) 106,
        (byte) 180,
        (byte) 241,
        (byte) 225,
        (byte) 230,
        (byte) 189,
        (byte) 69,
        (byte) 226,
        (byte) 244,
        (byte) 182,
        (byte) 102,
        (byte) 204,
        (byte) 149,
        (byte) 3,
        (byte) 86,
        (byte) 212,
        (byte) 28,
        (byte) 30,
        (byte) 215,
        (byte) 251,
        (byte) 195,
        (byte) 142,
        (byte) 181,
        (byte) 233,
        (byte) 207,
        (byte) 191,
        (byte) 186,
        (byte) 234,
        (byte) 119,
        (byte) 57,
        (byte) 175,
        (byte) 51,
        (byte) 201,
        (byte) 98,
        (byte) 113,
        (byte) 129,
        (byte) 121,
        (byte) 9,
        (byte) 173,
        (byte) 36,
        (byte) 205,
        (byte) 249,
        (byte) 216,
        (byte) 229,
        (byte) 197,
        (byte) 185,
        (byte) 77,
        (byte) 68,
        (byte) 8,
        (byte) 134,
        (byte) 231,
        (byte) 161,
        (byte) 29,
        (byte) 170,
        (byte) 237,
        (byte) 6,
        (byte) 112,
        (byte) 178,
        (byte) 210,
        (byte) 65,
        (byte) 123,
        (byte) 160,
        (byte) 17,
        (byte) 49,
        (byte) 194,
        (byte) 39,
        (byte) 144,
        (byte) 32,
        (byte) 246,
        (byte) 96,
        byte.MaxValue,
        (byte) 150,
        (byte) 92,
        (byte) 177,
        (byte) 171,
        (byte) 158,
        (byte) 156,
        (byte) 82,
        (byte) 27,
        (byte) 95,
        (byte) 147,
        (byte) 10,
        (byte) 239,
        (byte) 145,
        (byte) 133,
        (byte) 73,
        (byte) 238,
        (byte) 45,
        (byte) 79,
        (byte) 143,
        (byte) 59,
        (byte) 71,
        (byte) 135,
        (byte) 109,
        (byte) 70,
        (byte) 214,
        (byte) 62,
        (byte) 105,
        (byte) 100,
        (byte) 42,
        (byte) 206,
        (byte) 203,
        (byte) 47,
        (byte) 252,
        (byte) 151,
        (byte) 5,
        (byte) 122,
        (byte) 172,
        (byte) 127,
        (byte) 213,
        (byte) 26,
        (byte) 75,
        (byte) 14,
        (byte) 167,
        (byte) 90,
        (byte) 40,
        (byte) 20,
        (byte) 63,
        (byte) 41,
        (byte) 136,
        (byte) 60,
        (byte) 76,
        (byte) 2,
        (byte) 184,
        (byte) 218,
        (byte) 176,
        (byte) 23,
        (byte) 85,
        (byte) 31,
        (byte) 138,
        (byte) 125,
        (byte) 87,
        (byte) 199,
        (byte) 141,
        (byte) 116,
        (byte) 183,
        (byte) 196,
        (byte) 159,
        (byte) 114,
        (byte) 126,
        (byte) 21,
        (byte) 34,
        (byte) 18,
        (byte) 88,
        (byte) 7,
        (byte) 153,
        (byte) 52,
        (byte) 110,
        (byte) 80,
        (byte) 222,
        (byte) 104,
        (byte) 101,
        (byte) 188,
        (byte) 219,
        (byte) 248,
        (byte) 200,
        (byte) 168,
        (byte) 43,
        (byte) 64,
        (byte) 220,
        (byte) 254,
        (byte) 50,
        (byte) 164,
        (byte) 202,
        (byte) 16,
        (byte) 33,
        (byte) 240,
        (byte) 211,
        (byte) 93,
        (byte) 15,
        (byte) 0,
        (byte) 111,
        (byte) 157,
        (byte) 54,
        (byte) 66,
        (byte) 74,
        (byte) 94,
        (byte) 193,
        (byte) 224
      },
      {
        (byte) 117,
        (byte) 243,
        (byte) 198,
        (byte) 244,
        (byte) 219,
        (byte) 123,
        (byte) 251,
        (byte) 200,
        (byte) 74,
        (byte) 211,
        (byte) 230,
        (byte) 107,
        (byte) 69,
        (byte) 125,
        (byte) 232,
        (byte) 75,
        (byte) 214,
        (byte) 50,
        (byte) 216,
        (byte) 253,
        (byte) 55,
        (byte) 113,
        (byte) 241,
        (byte) 225,
        (byte) 48,
        (byte) 15,
        (byte) 248,
        (byte) 27,
        (byte) 135,
        (byte) 250,
        (byte) 6,
        (byte) 63,
        (byte) 94,
        (byte) 186,
        (byte) 174,
        (byte) 91,
        (byte) 138,
        (byte) 0,
        (byte) 188,
        (byte) 157,
        (byte) 109,
        (byte) 193,
        (byte) 177,
        (byte) 14,
        (byte) 128,
        (byte) 93,
        (byte) 210,
        (byte) 213,
        (byte) 160,
        (byte) 132,
        (byte) 7,
        (byte) 20,
        (byte) 181,
        (byte) 144,
        (byte) 44,
        (byte) 163,
        (byte) 178,
        (byte) 115,
        (byte) 76,
        (byte) 84,
        (byte) 146,
        (byte) 116,
        (byte) 54,
        (byte) 81,
        (byte) 56,
        (byte) 176,
        (byte) 189,
        (byte) 90,
        (byte) 252,
        (byte) 96,
        (byte) 98,
        (byte) 150,
        (byte) 108,
        (byte) 66,
        (byte) 247,
        (byte) 16,
        (byte) 124,
        (byte) 40,
        (byte) 39,
        (byte) 140,
        (byte) 19,
        (byte) 149,
        (byte) 156,
        (byte) 199,
        (byte) 36,
        (byte) 70,
        (byte) 59,
        (byte) 112,
        (byte) 202,
        (byte) 227,
        (byte) 133,
        (byte) 203,
        (byte) 17,
        (byte) 208,
        (byte) 147,
        (byte) 184,
        (byte) 166,
        (byte) 131,
        (byte) 32,
        byte.MaxValue,
        (byte) 159,
        (byte) 119,
        (byte) 195,
        (byte) 204,
        (byte) 3,
        (byte) 111,
        (byte) 8,
        (byte) 191,
        (byte) 64,
        (byte) 231,
        (byte) 43,
        (byte) 226,
        (byte) 121,
        (byte) 12,
        (byte) 170,
        (byte) 130,
        (byte) 65,
        (byte) 58,
        (byte) 234,
        (byte) 185,
        (byte) 228,
        (byte) 154,
        (byte) 164,
        (byte) 151,
        (byte) 126,
        (byte) 218,
        (byte) 122,
        (byte) 23,
        (byte) 102,
        (byte) 148,
        (byte) 161,
        (byte) 29,
        (byte) 61,
        (byte) 240,
        (byte) 222,
        (byte) 179,
        (byte) 11,
        (byte) 114,
        (byte) 167,
        (byte) 28,
        (byte) 239,
        (byte) 209,
        (byte) 83,
        (byte) 62,
        (byte) 143,
        (byte) 51,
        (byte) 38,
        (byte) 95,
        (byte) 236,
        (byte) 118,
        (byte) 42,
        (byte) 73,
        (byte) 129,
        (byte) 136,
        (byte) 238,
        (byte) 33,
        (byte) 196,
        (byte) 26,
        (byte) 235,
        (byte) 217,
        (byte) 197,
        (byte) 57,
        (byte) 153,
        (byte) 205,
        (byte) 173,
        (byte) 49,
        (byte) 139,
        (byte) 1,
        (byte) 24,
        (byte) 35,
        (byte) 221,
        (byte) 31,
        (byte) 78,
        (byte) 45,
        (byte) 249,
        (byte) 72,
        (byte) 79,
        (byte) 242,
        (byte) 101,
        (byte) 142,
        (byte) 120,
        (byte) 92,
        (byte) 88,
        (byte) 25,
        (byte) 141,
        (byte) 229,
        (byte) 152,
        (byte) 87,
        (byte) 103,
        (byte) 127,
        (byte) 5,
        (byte) 100,
        (byte) 175,
        (byte) 99,
        (byte) 182,
        (byte) 254,
        (byte) 245,
        (byte) 183,
        (byte) 60,
        (byte) 165,
        (byte) 206,
        (byte) 233,
        (byte) 104,
        (byte) 68,
        (byte) 224,
        (byte) 77,
        (byte) 67,
        (byte) 105,
        (byte) 41,
        (byte) 46,
        (byte) 172,
        (byte) 21,
        (byte) 89,
        (byte) 168,
        (byte) 10,
        (byte) 158,
        (byte) 110,
        (byte) 71,
        (byte) 223,
        (byte) 52,
        (byte) 53,
        (byte) 106,
        (byte) 207,
        (byte) 220,
        (byte) 34,
        (byte) 201,
        (byte) 192,
        (byte) 155,
        (byte) 137,
        (byte) 212,
        (byte) 237,
        (byte) 171,
        (byte) 18,
        (byte) 162,
        (byte) 13,
        (byte) 82,
        (byte) 187,
        (byte) 2,
        (byte) 47,
        (byte) 169,
        (byte) 215,
        (byte) 97,
        (byte) 30,
        (byte) 180,
        (byte) 80,
        (byte) 4,
        (byte) 246,
        (byte) 194,
        (byte) 22,
        (byte) 37,
        (byte) 134,
        (byte) 86,
        (byte) 85,
        (byte) 9,
        (byte) 190,
        (byte) 145
      }
    };
    protected int inputBlockSize = TwofishBase.BLOCK_SIZE / 8;
    protected int outputBlockSize = TwofishBase.BLOCK_SIZE / 8;
    private int[] numRounds = new int[4]
    {
      0,
      TwofishBase.ROUNDS_128,
      TwofishBase.ROUNDS_192,
      TwofishBase.ROUNDS_256
    };
    protected uint[] sboxKeys = new uint[TwofishBase.MAX_KEY_BITS / 64];
    protected uint[] subKeys = new uint[TwofishBase.TOTAL_SUBKEYS];
    protected uint[] Key = new uint[8];
    protected uint[] IV = new uint[4];
    protected CipherMode cipherMode = CipherMode.ECB;
    private int keyLength;
    private int rounds;

    private static uint f32(uint x, ref uint[] k32, int keyLen)
    {
      byte[] numArray = new byte[4]
      {
        TwofishBase.b0(x),
        TwofishBase.b1(x),
        TwofishBase.b2(x),
        TwofishBase.b3(x)
      };
      switch ((keyLen + 63) / 64 & 3)
      {
        case 0:
          numArray[0] = (byte) ((uint) TwofishBase.P8x8[TwofishBase.P_04, (int) numArray[0]] ^ (uint) TwofishBase.b0(k32[3]));
          numArray[1] = (byte) ((uint) TwofishBase.P8x8[TwofishBase.P_14, (int) numArray[1]] ^ (uint) TwofishBase.b1(k32[3]));
          numArray[2] = (byte) ((uint) TwofishBase.P8x8[TwofishBase.P_24, (int) numArray[2]] ^ (uint) TwofishBase.b2(k32[3]));
          numArray[3] = (byte) ((uint) TwofishBase.P8x8[TwofishBase.P_34, (int) numArray[3]] ^ (uint) TwofishBase.b3(k32[3]));
          goto case 3;
        case 2:
          numArray[0] = TwofishBase.P8x8[TwofishBase.P_00, (int) TwofishBase.P8x8[TwofishBase.P_01, (int) TwofishBase.P8x8[TwofishBase.P_02, (int) numArray[0]] ^ (int) TwofishBase.b0(k32[1])] ^ (int) TwofishBase.b0(k32[0])];
          numArray[1] = TwofishBase.P8x8[TwofishBase.P_10, (int) TwofishBase.P8x8[TwofishBase.P_11, (int) TwofishBase.P8x8[TwofishBase.P_12, (int) numArray[1]] ^ (int) TwofishBase.b1(k32[1])] ^ (int) TwofishBase.b1(k32[0])];
          numArray[2] = TwofishBase.P8x8[TwofishBase.P_20, (int) TwofishBase.P8x8[TwofishBase.P_21, (int) TwofishBase.P8x8[TwofishBase.P_22, (int) numArray[2]] ^ (int) TwofishBase.b2(k32[1])] ^ (int) TwofishBase.b2(k32[0])];
          numArray[3] = TwofishBase.P8x8[TwofishBase.P_30, (int) TwofishBase.P8x8[TwofishBase.P_31, (int) TwofishBase.P8x8[TwofishBase.P_32, (int) numArray[3]] ^ (int) TwofishBase.b3(k32[1])] ^ (int) TwofishBase.b3(k32[0])];
          break;
        case 3:
          numArray[0] = (byte) ((uint) TwofishBase.P8x8[TwofishBase.P_03, (int) numArray[0]] ^ (uint) TwofishBase.b0(k32[2]));
          numArray[1] = (byte) ((uint) TwofishBase.P8x8[TwofishBase.P_13, (int) numArray[1]] ^ (uint) TwofishBase.b1(k32[2]));
          numArray[2] = (byte) ((uint) TwofishBase.P8x8[TwofishBase.P_23, (int) numArray[2]] ^ (uint) TwofishBase.b2(k32[2]));
          numArray[3] = (byte) ((uint) TwofishBase.P8x8[TwofishBase.P_33, (int) numArray[3]] ^ (uint) TwofishBase.b3(k32[2]));
          goto case 2;
      }
      return (uint) (TwofishBase.M00((int) numArray[0]) ^ TwofishBase.M01((int) numArray[1]) ^ TwofishBase.M02((int) numArray[2]) ^ TwofishBase.M03((int) numArray[3]) ^ (TwofishBase.M10((int) numArray[0]) ^ TwofishBase.M11((int) numArray[1]) ^ TwofishBase.M12((int) numArray[2]) ^ TwofishBase.M13((int) numArray[3])) << 8 ^ (TwofishBase.M20((int) numArray[0]) ^ TwofishBase.M21((int) numArray[1]) ^ TwofishBase.M22((int) numArray[2]) ^ TwofishBase.M23((int) numArray[3])) << 16 ^ (TwofishBase.M30((int) numArray[0]) ^ TwofishBase.M31((int) numArray[1]) ^ TwofishBase.M32((int) numArray[2]) ^ TwofishBase.M33((int) numArray[3])) << 24);
    }

    protected bool reKey(int keyLen, ref uint[] key32)
    {
      this.keyLength = keyLen;
      this.rounds = this.numRounds[(keyLen - 1) / 64];
      int num1 = TwofishBase.ROUND_SUBKEYS + 2 * this.rounds;
      uint[] k32_1 = new uint[TwofishBase.MAX_KEY_BITS / 64];
      uint[] k32_2 = new uint[TwofishBase.MAX_KEY_BITS / 64];
      int num2 = (keyLen + 63) / 64;
      for (int index = 0; index < num2; ++index)
      {
        k32_1[index] = key32[2 * index];
        k32_2[index] = key32[2 * index + 1];
        this.sboxKeys[num2 - 1 - index] = TwofishBase.RS_MDS_Encode(k32_1[index], k32_2[index]);
      }
      for (int index = 0; index < num1 / 2; ++index)
      {
        uint num3 = TwofishBase.f32((uint) ((ulong) index * (ulong) TwofishBase.SK_STEP), ref k32_1, keyLen);
        uint num4 = TwofishBase.ROL(TwofishBase.f32((uint) ((ulong) index * (ulong) TwofishBase.SK_STEP + (ulong) TwofishBase.SK_BUMP), ref k32_2, keyLen), 8);
        this.subKeys[2 * index] = num3 + num4;
        this.subKeys[2 * index + 1] = TwofishBase.ROL(num3 + 2U * num4, TwofishBase.SK_ROTL);
      }
      return true;
    }

    protected void blockDecrypt(ref uint[] x)
    {
      uint[] numArray = new uint[4];
      if (this.cipherMode == CipherMode.CBC)
        x.CopyTo((Array) numArray, 0);
      for (int index = 0; index < TwofishBase.BLOCK_SIZE / 32; ++index)
        x[index] ^= this.subKeys[TwofishBase.OUTPUT_WHITEN + index];
      for (int index = this.rounds - 1; index >= 0; --index)
      {
        uint num1 = TwofishBase.f32(x[0], ref this.sboxKeys, this.keyLength);
        uint num2 = TwofishBase.f32(TwofishBase.ROL(x[1], 8), ref this.sboxKeys, this.keyLength);
        x[2] = TwofishBase.ROL(x[2], 1);
        x[2] ^= num1 + num2 + this.subKeys[TwofishBase.ROUND_SUBKEYS + 2 * index];
        x[3] ^= num1 + 2U * num2 + this.subKeys[TwofishBase.ROUND_SUBKEYS + 2 * index + 1];
        x[3] = TwofishBase.ROR(x[3], 1);
        if (index > 0)
        {
          uint num3 = x[0];
          x[0] = x[2];
          x[2] = num3;
          uint num4 = x[1];
          x[1] = x[3];
          x[3] = num4;
        }
      }
      for (int index = 0; index < TwofishBase.BLOCK_SIZE / 32; ++index)
      {
        x[index] ^= this.subKeys[TwofishBase.INPUT_WHITEN + index];
        if (this.cipherMode == CipherMode.CBC)
        {
          x[index] ^= this.IV[index];
          this.IV[index] = numArray[index];
        }
      }
    }

    protected void blockEncrypt(ref uint[] x)
    {
      for (int index = 0; index < TwofishBase.BLOCK_SIZE / 32; ++index)
      {
        x[index] ^= this.subKeys[TwofishBase.INPUT_WHITEN + index];
        if (this.cipherMode == CipherMode.CBC)
          x[index] ^= this.IV[index];
      }
      for (int index = 0; index < this.rounds; ++index)
      {
        uint num1 = TwofishBase.f32(x[0], ref this.sboxKeys, this.keyLength);
        uint num2 = TwofishBase.f32(TwofishBase.ROL(x[1], 8), ref this.sboxKeys, this.keyLength);
        x[3] = TwofishBase.ROL(x[3], 1);
        x[2] ^= num1 + num2 + this.subKeys[TwofishBase.ROUND_SUBKEYS + 2 * index];
        x[3] ^= num1 + 2U * num2 + this.subKeys[TwofishBase.ROUND_SUBKEYS + 2 * index + 1];
        x[2] = TwofishBase.ROR(x[2], 1);
        if (index < this.rounds - 1)
        {
          uint num3 = x[0];
          x[0] = x[2];
          x[2] = num3;
          uint num4 = x[1];
          x[1] = x[3];
          x[3] = num4;
        }
      }
      for (int index = 0; index < TwofishBase.BLOCK_SIZE / 32; ++index)
      {
        x[index] ^= this.subKeys[TwofishBase.OUTPUT_WHITEN + index];
        if (this.cipherMode == CipherMode.CBC)
          this.IV[index] = x[index];
      }
    }

    private static uint RS_MDS_Encode(uint k0, uint k1)
    {
      uint x;
      for (uint index1 = x = 0U; index1 < 2U; ++index1)
      {
        x ^= index1 > 0U ? k0 : k1;
        for (uint index2 = 0; index2 < 4U; ++index2)
          TwofishBase.RS_rem(ref x);
      }
      return x;
    }

    private static void RS_rem(ref uint x)
    {
      byte num1 = (byte) (x >> 24);
      uint num2 = (uint) (((ulong) ((int) num1 << 1) ^ (((int) num1 & 128) == 128 ? (ulong) TwofishBase.RS_GF_FDBK : 0UL)) & (ulong) byte.MaxValue);
      uint num3 = (uint) ((ulong) ((int) num1 >> 1 & (int) sbyte.MaxValue) ^ (((int) num1 & 1) == 1 ? (ulong) (TwofishBase.RS_GF_FDBK >> 1) : 0UL) ^ (ulong) num2);
      x = (uint) ((int) x << 8 ^ (int) num3 << 24 ^ (int) num2 << 16 ^ (int) num3 << 8) ^ (uint) num1;
    }

    private static int LFSR1(int x)
    {
      return x >> 1 ^ ((x & 1) == 1 ? TwofishBase.MDS_GF_FDBK / 2 : 0);
    }

    private static int LFSR2(int x)
    {
      return x >> 2 ^ ((x & 2) == 2 ? TwofishBase.MDS_GF_FDBK / 2 : 0) ^ ((x & 1) == 1 ? TwofishBase.MDS_GF_FDBK / 4 : 0);
    }

    private static int Mx_1(int x)
    {
      return x;
    }

    private static int Mx_X(int x)
    {
      return x ^ TwofishBase.LFSR2(x);
    }

    private static int Mx_Y(int x)
    {
      return x ^ TwofishBase.LFSR1(x) ^ TwofishBase.LFSR2(x);
    }

    private static int M00(int x)
    {
      return TwofishBase.Mul_1(x);
    }

    private static int M01(int x)
    {
      return TwofishBase.Mul_Y(x);
    }

    private static int M02(int x)
    {
      return TwofishBase.Mul_X(x);
    }

    private static int M03(int x)
    {
      return TwofishBase.Mul_X(x);
    }

    private static int M10(int x)
    {
      return TwofishBase.Mul_X(x);
    }

    private static int M11(int x)
    {
      return TwofishBase.Mul_Y(x);
    }

    private static int M12(int x)
    {
      return TwofishBase.Mul_Y(x);
    }

    private static int M13(int x)
    {
      return TwofishBase.Mul_1(x);
    }

    private static int M20(int x)
    {
      return TwofishBase.Mul_Y(x);
    }

    private static int M21(int x)
    {
      return TwofishBase.Mul_X(x);
    }

    private static int M22(int x)
    {
      return TwofishBase.Mul_1(x);
    }

    private static int M23(int x)
    {
      return TwofishBase.Mul_Y(x);
    }

    private static int M30(int x)
    {
      return TwofishBase.Mul_Y(x);
    }

    private static int M31(int x)
    {
      return TwofishBase.Mul_1(x);
    }

    private static int M32(int x)
    {
      return TwofishBase.Mul_Y(x);
    }

    private static int M33(int x)
    {
      return TwofishBase.Mul_X(x);
    }

    private static int Mul_1(int x)
    {
      return TwofishBase.Mx_1(x);
    }

    private static int Mul_X(int x)
    {
      return TwofishBase.Mx_X(x);
    }

    private static int Mul_Y(int x)
    {
      return TwofishBase.Mx_Y(x);
    }

    private static uint ROL(uint x, int n)
    {
      return x << n | x >> 32 - (n & 31);
    }

    private static uint ROR(uint x, int n)
    {
      return x >> n | x << 32 - (n & 31);
    }

    protected static byte b0(uint x)
    {
      return (byte) x;
    }

    protected static byte b1(uint x)
    {
      return (byte) (x >> 8);
    }

    protected static byte b2(uint x)
    {
      return (byte) (x >> 16);
    }

    protected static byte b3(uint x)
    {
      return (byte) (x >> 24);
    }

    public enum EncryptionDirection
    {
      Encrypting,
      Decrypting,
    }
  }
}
