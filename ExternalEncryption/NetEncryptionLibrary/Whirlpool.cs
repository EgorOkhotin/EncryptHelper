namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class Whirlpool : BlockHashAlgorithm
  {
    private WhirlpoolDigest digest = new WhirlpoolDigest();

    public override int HashSize
    {
      get
      {
        return 512;
      }
    }

    public Whirlpool()
      : base(64)
    {
      lock (this)
        this.Initialize();
    }

    public override void Initialize()
    {
      lock (this)
      {
        this.digest.Reset();
        base.Initialize();
      }
    }

    protected override void ProcessBlock(byte[] inputBuffer, int inputOffset)
    {
      lock (this)
        this.digest.BlockUpdate(inputBuffer, inputOffset, this.BlockSize);
    }

    protected override byte[] ProcessFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
      lock (this)
      {
        this.digest.BlockUpdate(inputBuffer, inputOffset, inputCount);
        byte[] output = new byte[this.digest.GetDigestSize()];
        this.digest.DoFinal(output, 0);
        return output;
      }
    }
  }
}
