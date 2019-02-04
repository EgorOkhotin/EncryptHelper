using System;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal sealed class WhirlpoolDigest : IDigest, IMemoable
  {
    private readonly long[] _rc = new long[11];
    private byte[] _buffer = new byte[64];
    private short[] _bitCount = new short[32];
    private long[] _hash = new long[8];
    private long[] _K = new long[8];
    private long[] _L = new long[8];
    private long[] _block = new long[8];
    private long[] _state = new long[8];
    private static readonly int[] SBOX = new int[256]
    {
      24,
      35,
      198,
      232,
      135,
      184,
      1,
      79,
      54,
      166,
      210,
      245,
      121,
      111,
      145,
      82,
      96,
      188,
      155,
      142,
      163,
      12,
      123,
      53,
      29,
      224,
      215,
      194,
      46,
      75,
      254,
      87,
      21,
      119,
      55,
      229,
      159,
      240,
      74,
      218,
      88,
      201,
      41,
      10,
      177,
      160,
      107,
      133,
      189,
      93,
      16,
      244,
      203,
      62,
      5,
      103,
      228,
      39,
      65,
      139,
      167,
      125,
      149,
      216,
      251,
      238,
      124,
      102,
      221,
      23,
      71,
      158,
      202,
      45,
      191,
      7,
      173,
      90,
      131,
      51,
      99,
      2,
      170,
      113,
      200,
      25,
      73,
      217,
      242,
      227,
      91,
      136,
      154,
      38,
      50,
      176,
      233,
      15,
      213,
      128,
      190,
      205,
      52,
      72,
      (int) byte.MaxValue,
      122,
      144,
      95,
      32,
      104,
      26,
      174,
      180,
      84,
      147,
      34,
      100,
      241,
      115,
      18,
      64,
      8,
      195,
      236,
      219,
      161,
      141,
      61,
      151,
      0,
      207,
      43,
      118,
      130,
      214,
      27,
      181,
      175,
      106,
      80,
      69,
      243,
      48,
      239,
      63,
      85,
      162,
      234,
      101,
      186,
      47,
      192,
      222,
      28,
      253,
      77,
      146,
      117,
      6,
      138,
      178,
      230,
      14,
      31,
      98,
      212,
      168,
      150,
      249,
      197,
      37,
      89,
      132,
      114,
      57,
      76,
      94,
      120,
      56,
      140,
      209,
      165,
      226,
      97,
      179,
      33,
      156,
      30,
      67,
      199,
      252,
      4,
      81,
      153,
      109,
      13,
      250,
      223,
      126,
      36,
      59,
      171,
      206,
      17,
      143,
      78,
      183,
      235,
      60,
      129,
      148,
      247,
      185,
      19,
      44,
      211,
      231,
      110,
      196,
      3,
      86,
      68,
      (int) sbyte.MaxValue,
      169,
      42,
      187,
      193,
      83,
      220,
      11,
      157,
      108,
      49,
      116,
      246,
      70,
      172,
      137,
      20,
      225,
      22,
      58,
      105,
      9,
      112,
      182,
      208,
      237,
      204,
      66,
      152,
      164,
      40,
      92,
      248,
      134
    };
    private static readonly long[] C0 = new long[256];
    private static readonly long[] C1 = new long[256];
    private static readonly long[] C2 = new long[256];
    private static readonly long[] C3 = new long[256];
    private static readonly long[] C4 = new long[256];
    private static readonly long[] C5 = new long[256];
    private static readonly long[] C6 = new long[256];
    private static readonly long[] C7 = new long[256];
    private static readonly short[] EIGHT = new short[32];
    private const int BYTE_LENGTH = 64;
    private const int DIGEST_LENGTH_BYTES = 64;
    private const int ROUNDS = 10;
    private const int REDUCTION_POLYNOMIAL = 285;
    private const int BITCOUNT_ARRAY_SIZE = 32;
    private int _bufferPos;

    static WhirlpoolDigest()
    {
      WhirlpoolDigest.EIGHT[31] = (short) 8;
      for (int index = 0; index < 256; ++index)
      {
        int num1 = WhirlpoolDigest.SBOX[index];
        int num2 = WhirlpoolDigest.maskWithReductionPolynomial(num1 << 1);
        int num3 = WhirlpoolDigest.maskWithReductionPolynomial(num2 << 1);
        int num4 = num3 ^ num1;
        int num5 = WhirlpoolDigest.maskWithReductionPolynomial(num3 << 1);
        int num6 = num5 ^ num1;
        WhirlpoolDigest.C0[index] = WhirlpoolDigest.packIntoLong(num1, num1, num3, num1, num5, num4, num2, num6);
        WhirlpoolDigest.C1[index] = WhirlpoolDigest.packIntoLong(num6, num1, num1, num3, num1, num5, num4, num2);
        WhirlpoolDigest.C2[index] = WhirlpoolDigest.packIntoLong(num2, num6, num1, num1, num3, num1, num5, num4);
        WhirlpoolDigest.C3[index] = WhirlpoolDigest.packIntoLong(num4, num2, num6, num1, num1, num3, num1, num5);
        WhirlpoolDigest.C4[index] = WhirlpoolDigest.packIntoLong(num5, num4, num2, num6, num1, num1, num3, num1);
        WhirlpoolDigest.C5[index] = WhirlpoolDigest.packIntoLong(num1, num5, num4, num2, num6, num1, num1, num3);
        WhirlpoolDigest.C6[index] = WhirlpoolDigest.packIntoLong(num3, num1, num5, num4, num2, num6, num1, num1);
        WhirlpoolDigest.C7[index] = WhirlpoolDigest.packIntoLong(num1, num3, num1, num5, num4, num2, num6, num1);
      }
    }

    public WhirlpoolDigest()
    {
      this._rc[0] = 0L;
      for (int index1 = 1; index1 <= 10; ++index1)
      {
        int index2 = 8 * (index1 - 1);
        this._rc[index1] = WhirlpoolDigest.C0[index2] & -72057594037927936L ^ WhirlpoolDigest.C1[index2 + 1] & 71776119061217280L ^ WhirlpoolDigest.C2[index2 + 2] & 280375465082880L ^ WhirlpoolDigest.C3[index2 + 3] & 1095216660480L ^ WhirlpoolDigest.C4[index2 + 4] & 4278190080L ^ WhirlpoolDigest.C5[index2 + 5] & 16711680L ^ WhirlpoolDigest.C6[index2 + 6] & 65280L ^ WhirlpoolDigest.C7[index2 + 7] & (long) byte.MaxValue;
      }
    }

    private static long packIntoLong(int b7, int b6, int b5, int b4, int b3, int b2, int b1, int b0)
    {
      return (long) b7 << 56 ^ (long) b6 << 48 ^ (long) b5 << 40 ^ (long) b4 << 32 ^ (long) b3 << 24 ^ (long) b2 << 16 ^ (long) b1 << 8 ^ (long) b0;
    }

    private static int maskWithReductionPolynomial(int input)
    {
      int num = input;
      if (num >= 256)
        num ^= 285;
      return num;
    }

    public WhirlpoolDigest(WhirlpoolDigest originalDigest)
    {
      this.Reset((IMemoable) originalDigest);
    }

    public string AlgorithmName
    {
      get
      {
        return "Whirlpool";
      }
    }

    public int GetDigestSize()
    {
      return 64;
    }

    public int DoFinal(byte[] output, int outOff)
    {
      this.finish();
      for (int index = 0; index < 8; ++index)
        WhirlpoolDigest.convertLongToByteArray(this._hash[index], output, outOff + index * 8);
      this.Reset();
      return this.GetDigestSize();
    }

    public void Reset()
    {
      this._bufferPos = 0;
      Array.Clear((Array) this._bitCount, 0, this._bitCount.Length);
      Array.Clear((Array) this._buffer, 0, this._buffer.Length);
      Array.Clear((Array) this._hash, 0, this._hash.Length);
      Array.Clear((Array) this._K, 0, this._K.Length);
      Array.Clear((Array) this._L, 0, this._L.Length);
      Array.Clear((Array) this._block, 0, this._block.Length);
      Array.Clear((Array) this._state, 0, this._state.Length);
    }

    private void processFilledBuffer()
    {
      for (int index = 0; index < this._state.Length; ++index)
        this._block[index] = WhirlpoolDigest.bytesToLongFromBuffer(this._buffer, index * 8);
      this.processBlock();
      this._bufferPos = 0;
      Array.Clear((Array) this._buffer, 0, this._buffer.Length);
    }

    private static long bytesToLongFromBuffer(byte[] buffer, int startPos)
    {
      return ((long) buffer[startPos] & (long) byte.MaxValue) << 56 | ((long) buffer[startPos + 1] & (long) byte.MaxValue) << 48 | ((long) buffer[startPos + 2] & (long) byte.MaxValue) << 40 | ((long) buffer[startPos + 3] & (long) byte.MaxValue) << 32 | ((long) buffer[startPos + 4] & (long) byte.MaxValue) << 24 | ((long) buffer[startPos + 5] & (long) byte.MaxValue) << 16 | ((long) buffer[startPos + 6] & (long) byte.MaxValue) << 8 | (long) buffer[startPos + 7] & (long) byte.MaxValue;
    }

    private static void convertLongToByteArray(long inputLong, byte[] outputArray, int offSet)
    {
      for (int index = 0; index < 8; ++index)
        outputArray[offSet + index] = (byte) ((ulong) (inputLong >> 56 - index * 8) & (ulong) byte.MaxValue);
    }

    private void processBlock()
    {
      for (int index = 0; index < 8; ++index)
        this._state[index] = this._block[index] ^ (this._K[index] = this._hash[index]);
      for (int index1 = 1; index1 <= 10; ++index1)
      {
        for (int index2 = 0; index2 < 8; ++index2)
        {
          this._L[index2] = 0L;
          this._L[index2] ^= WhirlpoolDigest.C0[(int) (this._K[index2 & 7] >> 56) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C1[(int) (this._K[index2 - 1 & 7] >> 48) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C2[(int) (this._K[index2 - 2 & 7] >> 40) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C3[(int) (this._K[index2 - 3 & 7] >> 32) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C4[(int) (this._K[index2 - 4 & 7] >> 24) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C5[(int) (this._K[index2 - 5 & 7] >> 16) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C6[(int) (this._K[index2 - 6 & 7] >> 8) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C7[(int) this._K[index2 - 7 & 7] & (int) byte.MaxValue];
        }
        Array.Copy((Array) this._L, 0, (Array) this._K, 0, this._K.Length);
        this._K[0] ^= this._rc[index1];
        for (int index2 = 0; index2 < 8; ++index2)
        {
          this._L[index2] = this._K[index2];
          this._L[index2] ^= WhirlpoolDigest.C0[(int) (this._state[index2 & 7] >> 56) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C1[(int) (this._state[index2 - 1 & 7] >> 48) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C2[(int) (this._state[index2 - 2 & 7] >> 40) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C3[(int) (this._state[index2 - 3 & 7] >> 32) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C4[(int) (this._state[index2 - 4 & 7] >> 24) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C5[(int) (this._state[index2 - 5 & 7] >> 16) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C6[(int) (this._state[index2 - 6 & 7] >> 8) & (int) byte.MaxValue];
          this._L[index2] ^= WhirlpoolDigest.C7[(int) this._state[index2 - 7 & 7] & (int) byte.MaxValue];
        }
        Array.Copy((Array) this._L, 0, (Array) this._state, 0, this._state.Length);
      }
      for (int index = 0; index < 8; ++index)
        this._hash[index] ^= this._state[index] ^ this._block[index];
    }

    public void Update(byte input)
    {
      this._buffer[this._bufferPos] = input;
      ++this._bufferPos;
      if (this._bufferPos == this._buffer.Length)
        this.processFilledBuffer();
      this.increment();
    }

    private void increment()
    {
      int num1 = 0;
      for (int index = this._bitCount.Length - 1; index >= 0; --index)
      {
        int num2 = ((int) this._bitCount[index] & (int) byte.MaxValue) + (int) WhirlpoolDigest.EIGHT[index] + num1;
        num1 = num2 >> 8;
        this._bitCount[index] = (short) (num2 & (int) byte.MaxValue);
      }
    }

    public void BlockUpdate(byte[] input, int inOff, int length)
    {
      for (; length > 0; --length)
      {
        this.Update(input[inOff]);
        ++inOff;
      }
    }

    private void finish()
    {
      byte[] numArray = this.copyBitLength();
      this._buffer[this._bufferPos++] |= (byte) 128;
      if (this._bufferPos == this._buffer.Length)
        this.processFilledBuffer();
      if (this._bufferPos > 32)
      {
        while (this._bufferPos != 0)
          this.Update((byte) 0);
      }
      while (this._bufferPos <= 32)
        this.Update((byte) 0);
      Array.Copy((Array) numArray, 0, (Array) this._buffer, 32, numArray.Length);
      this.processFilledBuffer();
    }

    private byte[] copyBitLength()
    {
      byte[] numArray = new byte[32];
      for (int index = 0; index < numArray.Length; ++index)
        numArray[index] = (byte) ((uint) this._bitCount[index] & (uint) byte.MaxValue);
      return numArray;
    }

    public int GetByteLength()
    {
      return 64;
    }

    public IMemoable Copy()
    {
      return (IMemoable) new WhirlpoolDigest(this);
    }

    public void Reset(IMemoable other)
    {
      WhirlpoolDigest whirlpoolDigest = (WhirlpoolDigest) other;
      Array.Copy((Array) whirlpoolDigest._rc, 0, (Array) this._rc, 0, this._rc.Length);
      Array.Copy((Array) whirlpoolDigest._buffer, 0, (Array) this._buffer, 0, this._buffer.Length);
      this._bufferPos = whirlpoolDigest._bufferPos;
      Array.Copy((Array) whirlpoolDigest._bitCount, 0, (Array) this._bitCount, 0, this._bitCount.Length);
      Array.Copy((Array) whirlpoolDigest._hash, 0, (Array) this._hash, 0, this._hash.Length);
      Array.Copy((Array) whirlpoolDigest._K, 0, (Array) this._K, 0, this._K.Length);
      Array.Copy((Array) whirlpoolDigest._L, 0, (Array) this._L, 0, this._L.Length);
      Array.Copy((Array) whirlpoolDigest._block, 0, (Array) this._block, 0, this._block.Length);
      Array.Copy((Array) whirlpoolDigest._state, 0, (Array) this._state, 0, this._state.Length);
    }
  }
}
