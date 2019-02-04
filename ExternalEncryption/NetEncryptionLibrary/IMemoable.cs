namespace ExternalEncryption.NetEncryptionLibrary
{
  internal interface IMemoable
  {
    IMemoable Copy();

    void Reset(IMemoable other);
  }
}
