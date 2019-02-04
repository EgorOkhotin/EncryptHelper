using ExternalEncryption.NetEncryptionLibrary;
using ExternalEncryption.NetEncryptionLibrary.AsymmetricEncryption;
using System;

namespace KellermanSoftware.NetEncryptionLibrary
{
  internal class EncryptionFactory
  {
    public static IEncryption CreateEncryption(EncryptionProvider provider)
    {
      if (provider == EncryptionProvider.RSA)
        return (IEncryption) new RsaEncryption();
      throw new NotSupportedException("Provider not supported: " + provider.ToString());
    }
  }
}
