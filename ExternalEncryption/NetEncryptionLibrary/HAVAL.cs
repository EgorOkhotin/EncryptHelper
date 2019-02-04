using System;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class HAVAL : BlockHashAlgorithm
  {
    private HAVALParameters parameters;
    private uint[] accumulator;

    public new int HashSize { get; set; }

    public HAVAL(HAVALParameters param)
      : base(128)
    {
      lock (this)
      {
        if (param == null)
          throw new ArgumentNullException(nameof (param), "The HAVALParameters cannot be null.");
        this.HashSize = (int) param.Length;
        this.parameters = param;
        this.accumulator = new uint[8];
        this.Initialize();
      }
    }

    public override void Initialize()
    {
      lock (this)
      {
        this.accumulator[0] = 608135816U;
        this.accumulator[1] = 2242054355U;
        this.accumulator[2] = 320440878U;
        this.accumulator[3] = 57701188U;
        this.accumulator[4] = 2752067618U;
        this.accumulator[5] = 698298832U;
        this.accumulator[6] = 137296536U;
        this.accumulator[7] = 3964562569U;
        base.Initialize();
      }
    }

    protected override void ProcessBlock(byte[] inputBuffer, int inputOffset)
    {
      lock (this)
        this.Transform(Utilities.ByteToUInt(inputBuffer, inputOffset, this.BlockSize));
    }

    protected override byte[] ProcessFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
      lock (this)
      {
        long num1 = this.Count + (long) inputCount;
        int num2 = this.BlockSize - 10 - (int) ((ulong) num1 % (ulong) this.BlockSize);
        if (num2 < 1)
          num2 += this.BlockSize;
        byte[] inputBuffer1 = new byte[inputCount + num2 + 10];
        Array.Copy((Array) inputBuffer, inputOffset, (Array) inputBuffer1, 0, inputCount);
        inputBuffer1[inputCount] = (byte) 1;
        inputBuffer1[inputCount + num2] = (byte) (((int) this.parameters.Length & 3) << 6 | ((int) this.parameters.Passes & 7) << 3 | 1);
        inputBuffer1[inputCount + num2 + 1] = (byte) ((int) this.parameters.Length >> 2 & (int) byte.MaxValue);
        Array.Copy((Array) Utilities.ULongToByte((ulong) num1 * 8UL), 0, (Array) inputBuffer1, inputCount + num2 + 2, 8);
        this.ProcessBlock(inputBuffer1, 0);
        if (inputBuffer1.Length == this.BlockSize * 2)
          this.ProcessBlock(inputBuffer1, this.BlockSize);
        this.FoldHash();
        return Utilities.UIntToByte(this.accumulator, 0, (int) this.parameters.Length / 32);
      }
    }

    private uint F1(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
    {
      return (uint) ((int) x1 & ((int) x0 ^ (int) x4) ^ (int) x2 & (int) x5 ^ (int) x3 & (int) x6) ^ x0;
    }

    private uint F2(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
    {
      return (uint) ((int) x2 & ((int) x1 & ~(int) x3 ^ (int) x4 & (int) x5 ^ (int) x6 ^ (int) x0) ^ ((int) x4 & ((int) x1 ^ (int) x5) ^ (int) x3 & (int) x5 ^ (int) x0));
    }

    private uint F3(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
    {
      return (uint) ((int) x3 & ((int) x1 & (int) x2 ^ (int) x6 ^ (int) x0) ^ (int) x1 & (int) x4 ^ (int) x2 & (int) x5) ^ x0;
    }

    private uint F4(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
    {
      return (uint) ((int) x4 & ((int) x5 & ~(int) x2 ^ (int) x3 & ~(int) x6 ^ (int) x1 ^ (int) x6 ^ (int) x0) ^ ((int) x3 & ((int) x1 & (int) x2 ^ (int) x5 ^ (int) x6) ^ (int) x2 & (int) x6 ^ (int) x0));
    }

    private uint F5(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
    {
      return (uint) ((int) x0 & ((int) x1 & (int) x2 & (int) x3 ^ ~(int) x5) ^ (int) x1 & (int) x4 ^ (int) x2 & (int) x5 ^ (int) x3 & (int) x6);
    }

    private uint FF1(uint x7, uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0, uint w)
    {
      return Utilities.RotateRight(this.parameters.Passes != (short) 3 ? (this.parameters.Passes != (short) 4 ? this.F1(x3, x4, x1, x0, x5, x2, x6) : this.F1(x2, x6, x1, x4, x5, x3, x0)) : this.F1(x1, x0, x3, x5, x6, x2, x4), 7) + Utilities.RotateRight(x7, 11) + w;
    }

    private uint FF2(uint x7, uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0, uint w, uint c)
    {
      return Utilities.RotateRight(this.parameters.Passes != (short) 3 ? (this.parameters.Passes != (short) 4 ? this.F2(x6, x2, x1, x0, x3, x4, x5) : this.F2(x3, x5, x2, x0, x1, x6, x4)) : this.F2(x4, x2, x1, x0, x5, x3, x6), 7) + Utilities.RotateRight(x7, 11) + w + c;
    }

    private uint FF3(uint x7, uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0, uint w, uint c)
    {
      return Utilities.RotateRight(this.parameters.Passes != (short) 3 ? (this.parameters.Passes != (short) 4 ? this.F3(x2, x6, x0, x4, x3, x1, x5) : this.F3(x1, x4, x3, x6, x0, x2, x5)) : this.F3(x6, x1, x2, x3, x4, x5, x0), 7) + Utilities.RotateRight(x7, 11) + w + c;
    }

    private uint FF4(uint x7, uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0, uint w, uint c)
    {
      return Utilities.RotateRight(this.parameters.Passes != (short) 4 ? this.F4(x1, x5, x3, x2, x0, x4, x6) : this.F4(x6, x4, x0, x5, x2, x1, x3), 7) + Utilities.RotateRight(x7, 11) + w + c;
    }

    private uint FF5(uint x7, uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0, uint w, uint c)
    {
      return Utilities.RotateRight(this.F5(x2, x5, x0, x6, x4, x3, x1), 7) + Utilities.RotateRight(x7, 11) + w + c;
    }

    private void Transform(uint[] inputBuffer)
    {
      uint[] numArray = new uint[this.accumulator.Length];
      Array.Copy((Array) this.accumulator, 0, (Array) numArray, 0, this.accumulator.Length);
      numArray[7] = this.FF1(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[0]);
      numArray[6] = this.FF1(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[1]);
      numArray[5] = this.FF1(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[2]);
      numArray[4] = this.FF1(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[3]);
      numArray[3] = this.FF1(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[4]);
      numArray[2] = this.FF1(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[5]);
      numArray[1] = this.FF1(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[6]);
      numArray[0] = this.FF1(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[7]);
      numArray[7] = this.FF1(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[8]);
      numArray[6] = this.FF1(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[9]);
      numArray[5] = this.FF1(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[10]);
      numArray[4] = this.FF1(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[11]);
      numArray[3] = this.FF1(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[12]);
      numArray[2] = this.FF1(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[13]);
      numArray[1] = this.FF1(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[14]);
      numArray[0] = this.FF1(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[15]);
      numArray[7] = this.FF1(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[16]);
      numArray[6] = this.FF1(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[17]);
      numArray[5] = this.FF1(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[18]);
      numArray[4] = this.FF1(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[19]);
      numArray[3] = this.FF1(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[20]);
      numArray[2] = this.FF1(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[21]);
      numArray[1] = this.FF1(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[22]);
      numArray[0] = this.FF1(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[23]);
      numArray[7] = this.FF1(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[24]);
      numArray[6] = this.FF1(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[25]);
      numArray[5] = this.FF1(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[26]);
      numArray[4] = this.FF1(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[27]);
      numArray[3] = this.FF1(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[28]);
      numArray[2] = this.FF1(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[29]);
      numArray[1] = this.FF1(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[30]);
      numArray[0] = this.FF1(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[31]);
      numArray[7] = this.FF2(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[5], 1160258022U);
      numArray[6] = this.FF2(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[14], 953160567U);
      numArray[5] = this.FF2(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[26], 3193202383U);
      numArray[4] = this.FF2(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[18], 887688300U);
      numArray[3] = this.FF2(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[11], 3232508343U);
      numArray[2] = this.FF2(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[28], 3380367581U);
      numArray[1] = this.FF2(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[7], 1065670069U);
      numArray[0] = this.FF2(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[16], 3041331479U);
      numArray[7] = this.FF2(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[0], 2450970073U);
      numArray[6] = this.FF2(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[23], 2306472731U);
      numArray[5] = this.FF2(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[20], 3509652390U);
      numArray[4] = this.FF2(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[22], 2564797868U);
      numArray[3] = this.FF2(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[1], 805139163U);
      numArray[2] = this.FF2(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[10], 3491422135U);
      numArray[1] = this.FF2(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[4], 3101798381U);
      numArray[0] = this.FF2(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[8], 1780907670U);
      numArray[7] = this.FF2(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[30], 3128725573U);
      numArray[6] = this.FF2(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[3], 4046225305U);
      numArray[5] = this.FF2(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[21], 614570311U);
      numArray[4] = this.FF2(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[9], 3012652279U);
      numArray[3] = this.FF2(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[17], 134345442U);
      numArray[2] = this.FF2(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[24], 2240740374U);
      numArray[1] = this.FF2(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[29], 1667834072U);
      numArray[0] = this.FF2(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[6], 1901547113U);
      numArray[7] = this.FF2(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[19], 2757295779U);
      numArray[6] = this.FF2(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[12], 4103290238U);
      numArray[5] = this.FF2(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[15], 227898511U);
      numArray[4] = this.FF2(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[13], 1921955416U);
      numArray[3] = this.FF2(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[2], 1904987480U);
      numArray[2] = this.FF2(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[25], 2182433518U);
      numArray[1] = this.FF2(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[31], 2069144605U);
      numArray[0] = this.FF2(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[27], 3260701109U);
      numArray[7] = this.FF3(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[19], 2620446009U);
      numArray[6] = this.FF3(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[9], 720527379U);
      numArray[5] = this.FF3(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[4], 3318853667U);
      numArray[4] = this.FF3(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[20], 677414384U);
      numArray[3] = this.FF3(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[28], 3393288472U);
      numArray[2] = this.FF3(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[17], 3101374703U);
      numArray[1] = this.FF3(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[8], 2390351024U);
      numArray[0] = this.FF3(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[22], 1614419982U);
      numArray[7] = this.FF3(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[29], 1822297739U);
      numArray[6] = this.FF3(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[14], 2954791486U);
      numArray[5] = this.FF3(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[25], 3608508353U);
      numArray[4] = this.FF3(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[12], 3174124327U);
      numArray[3] = this.FF3(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[24], 2024746970U);
      numArray[2] = this.FF3(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[30], 1432378464U);
      numArray[1] = this.FF3(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[16], 3864339955U);
      numArray[0] = this.FF3(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[26], 2857741204U);
      numArray[7] = this.FF3(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[31], 1464375394U);
      numArray[6] = this.FF3(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[15], 1676153920U);
      numArray[5] = this.FF3(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[7], 1439316330U);
      numArray[4] = this.FF3(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[3], 715854006U);
      numArray[3] = this.FF3(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[1], 3033291828U);
      numArray[2] = this.FF3(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[0], 289532110U);
      numArray[1] = this.FF3(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[18], 2706671279U);
      numArray[0] = this.FF3(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[27], 2087905683U);
      numArray[7] = this.FF3(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[13], 3018724369U);
      numArray[6] = this.FF3(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[6], 1668267050U);
      numArray[5] = this.FF3(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[21], 732546397U);
      numArray[4] = this.FF3(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[10], 1947742710U);
      numArray[3] = this.FF3(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[23], 3462151702U);
      numArray[2] = this.FF3(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[11], 2609353502U);
      numArray[1] = this.FF3(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[5], 2950085171U);
      numArray[0] = this.FF3(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[2], 1814351708U);
      if (this.parameters.Passes >= (short) 4)
      {
        numArray[7] = this.FF4(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[24], 2050118529U);
        numArray[6] = this.FF4(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[4], 680887927U);
        numArray[5] = this.FF4(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[0], 999245976U);
        numArray[4] = this.FF4(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[14], 1800124847U);
        numArray[3] = this.FF4(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[2], 3300911131U);
        numArray[2] = this.FF4(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[7], 1713906067U);
        numArray[1] = this.FF4(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[28], 1641548236U);
        numArray[0] = this.FF4(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[23], 4213287313U);
        numArray[7] = this.FF4(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[26], 1216130144U);
        numArray[6] = this.FF4(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[6], 1575780402U);
        numArray[5] = this.FF4(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[30], 4018429277U);
        numArray[4] = this.FF4(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[20], 3917837745U);
        numArray[3] = this.FF4(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[18], 3693486850U);
        numArray[2] = this.FF4(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[25], 3949271944U);
        numArray[1] = this.FF4(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[19], 596196993U);
        numArray[0] = this.FF4(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[3], 3549867205U);
        numArray[7] = this.FF4(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[22], 258830323U);
        numArray[6] = this.FF4(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[11], 2213823033U);
        numArray[5] = this.FF4(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[31], 772490370U);
        numArray[4] = this.FF4(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[21], 2760122372U);
        numArray[3] = this.FF4(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[8], 1774776394U);
        numArray[2] = this.FF4(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[27], 2652871518U);
        numArray[1] = this.FF4(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[12], 566650946U);
        numArray[0] = this.FF4(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[9], 4142492826U);
        numArray[7] = this.FF4(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[1], 1728879713U);
        numArray[6] = this.FF4(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[29], 2882767088U);
        numArray[5] = this.FF4(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[5], 1783734482U);
        numArray[4] = this.FF4(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[15], 3629395816U);
        numArray[3] = this.FF4(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[17], 2517608232U);
        numArray[2] = this.FF4(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[10], 2874225571U);
        numArray[1] = this.FF4(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[16], 1861159788U);
        numArray[0] = this.FF4(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[13], 326777828U);
      }
      if (this.parameters.Passes == (short) 5)
      {
        numArray[7] = this.FF5(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[27], 3124490320U);
        numArray[6] = this.FF5(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[3], 2130389656U);
        numArray[5] = this.FF5(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[21], 2716951837U);
        numArray[4] = this.FF5(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[26], 967770486U);
        numArray[3] = this.FF5(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[17], 1724537150U);
        numArray[2] = this.FF5(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[11], 2185432712U);
        numArray[1] = this.FF5(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[20], 2364442137U);
        numArray[0] = this.FF5(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[29], 1164943284U);
        numArray[7] = this.FF5(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[19], 2105845187U);
        numArray[6] = this.FF5(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[0], 998989502U);
        numArray[5] = this.FF5(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[12], 3765401048U);
        numArray[4] = this.FF5(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[7], 2244026483U);
        numArray[3] = this.FF5(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[13], 1075463327U);
        numArray[2] = this.FF5(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[8], 1455516326U);
        numArray[1] = this.FF5(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[31], 1322494562U);
        numArray[0] = this.FF5(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[10], 910128902U);
        numArray[7] = this.FF5(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[5], 469688178U);
        numArray[6] = this.FF5(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[9], 1117454909U);
        numArray[5] = this.FF5(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[14], 936433444U);
        numArray[4] = this.FF5(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[30], 3490320968U);
        numArray[3] = this.FF5(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[18], 3675253459U);
        numArray[2] = this.FF5(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[6], 1240580251U);
        numArray[1] = this.FF5(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[28], 122909385U);
        numArray[0] = this.FF5(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[24], 2157517691U);
        numArray[7] = this.FF5(numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], inputBuffer[2], 634681816U);
        numArray[6] = this.FF5(numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], inputBuffer[23], 4142456567U);
        numArray[5] = this.FF5(numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], inputBuffer[16], 3825094682U);
        numArray[4] = this.FF5(numArray[4], numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], inputBuffer[22], 3061402683U);
        numArray[3] = this.FF5(numArray[3], numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], inputBuffer[4], 2540495037U);
        numArray[2] = this.FF5(numArray[2], numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], inputBuffer[1], 79693498U);
        numArray[1] = this.FF5(numArray[1], numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], inputBuffer[25], 3249098678U);
        numArray[0] = this.FF5(numArray[0], numArray[7], numArray[6], numArray[5], numArray[4], numArray[3], numArray[2], numArray[1], inputBuffer[15], 1084186820U);
      }
      for (int index = 0; index < this.accumulator.Length; ++index)
        this.accumulator[index] += numArray[index];
    }

    private void FoldHash()
    {
      if (this.parameters.Length == (short) 128)
      {
        this.accumulator[0] += Utilities.RotateRight((uint) ((int) this.accumulator[7] & (int) byte.MaxValue | (int) this.accumulator[6] & -16777216 | (int) this.accumulator[5] & 16711680 | (int) this.accumulator[4] & 65280), 8);
        this.accumulator[1] += Utilities.RotateRight((uint) ((int) this.accumulator[7] & 65280 | (int) this.accumulator[6] & (int) byte.MaxValue | (int) this.accumulator[5] & -16777216 | (int) this.accumulator[4] & 16711680), 16);
        this.accumulator[2] += Utilities.RotateRight((uint) ((int) this.accumulator[7] & 16711680 | (int) this.accumulator[6] & 65280 | (int) this.accumulator[5] & (int) byte.MaxValue | (int) this.accumulator[4] & -16777216), 24);
        this.accumulator[3] += (uint) ((int) this.accumulator[7] & -16777216 | (int) this.accumulator[6] & 16711680 | (int) this.accumulator[5] & 65280 | (int) this.accumulator[4] & (int) byte.MaxValue);
      }
      else if (this.parameters.Length == (short) 160)
      {
        this.accumulator[0] += Utilities.RotateRight((uint) ((ulong) (this.accumulator[7] & 63U) | (ulong) this.accumulator[6] & 18446744073675997184UL | (ulong) (this.accumulator[5] & 33030144U)), 19);
        this.accumulator[1] += Utilities.RotateRight((uint) ((ulong) (uint) ((int) this.accumulator[7] & 4032 | (int) this.accumulator[6] & 63) | (ulong) this.accumulator[5] & 18446744073675997184UL), 25);
        this.accumulator[2] += (uint) ((int) this.accumulator[7] & 520192 | (int) this.accumulator[6] & 4032 | (int) this.accumulator[5] & 63);
        this.accumulator[3] += (uint) ((int) this.accumulator[7] & 33030144 | (int) this.accumulator[6] & 520192 | (int) this.accumulator[5] & 4032) >> 6;
        this.accumulator[4] += (uint) ((ulong) this.accumulator[7] & 18446744073675997184UL | (ulong) (this.accumulator[6] & 33030144U) | (ulong) (this.accumulator[5] & 520192U)) >> 12;
      }
      else if (this.parameters.Length == (short) 192)
      {
        this.accumulator[0] += Utilities.RotateRight((uint) ((ulong) (this.accumulator[7] & 31U) | (ulong) this.accumulator[6] & 18446744073642442752UL), 26);
        this.accumulator[1] += (uint) ((int) this.accumulator[7] & 992 | (int) this.accumulator[6] & 31);
        this.accumulator[2] += (uint) ((int) this.accumulator[7] & 64512 | (int) this.accumulator[6] & 992) >> 5;
        this.accumulator[3] += (uint) ((int) this.accumulator[7] & 2031616 | (int) this.accumulator[6] & 64512) >> 10;
        this.accumulator[4] += (uint) ((int) this.accumulator[7] & 65011712 | (int) this.accumulator[6] & 2031616) >> 16;
        this.accumulator[5] += (uint) ((ulong) this.accumulator[7] & 18446744073642442752UL | (ulong) (this.accumulator[6] & 65011712U)) >> 21;
      }
      else
      {
        if (this.parameters.Length != (short) 224)
          return;
        this.accumulator[0] += this.accumulator[7] >> 27 & 31U;
        this.accumulator[1] += this.accumulator[7] >> 22 & 31U;
        this.accumulator[2] += this.accumulator[7] >> 18 & 15U;
        this.accumulator[3] += this.accumulator[7] >> 13 & 31U;
        this.accumulator[4] += this.accumulator[7] >> 9 & 15U;
        this.accumulator[5] += this.accumulator[7] >> 4 & 31U;
        this.accumulator[6] += this.accumulator[7] & 15U;
      }
    }
  }
}
