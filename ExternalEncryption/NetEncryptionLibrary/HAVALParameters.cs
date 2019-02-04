using System;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal class HAVALParameters : HashAlgorithmParameters
  {
    private short passes;
    private short length;

    public short Passes
    {
      get
      {
        return this.passes;
      }
      set
      {
        if (value != (short) 3 && value != (short) 4 && value != (short) 5)
          throw new ArgumentException("The number of passes can only be 3, 4, or 5.", nameof (Passes));
        this.passes = value;
      }
    }

    public short Length
    {
      get
      {
        return this.length;
      }
      set
      {
        if (value != (short) 128 && value != (short) 160 && (value != (short) 192 && value != (short) 224) && value != (short) 256)
          throw new ArgumentException("The HAVAL bit length can only be 128, 160, 192, 224, or 256 bits long.", nameof (Length));
        this.length = value;
      }
    }

    public HAVALParameters(short passes, short length)
    {
      this.Passes = passes;
      this.Length = length;
    }

    public static HAVALParameters GetParameters()
    {
      return new HAVALParameters((short) 3, (short) 128);
    }
  }
}
