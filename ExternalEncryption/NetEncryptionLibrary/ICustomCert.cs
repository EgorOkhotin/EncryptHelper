namespace ExternalEncryption.NetEncryptionLibrary
{
  internal interface ICustomCert
  {
    void ICustomCert(string initializationVector, string salt);

    string PublicKey { get; set; }

    string PrivateKey { get; set; }
  }
}
