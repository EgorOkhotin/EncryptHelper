// Decompiled with JetBrains decompiler
// Type: KellermanSoftware.NetEncryptionLibrary.IPublicKeyEncryption
// Assembly: KellermanSoftware.NET-Encryption-Library-Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: F7015153-C9B6-47CF-A891-816AAF547510
// Assembly location: D:\Temp\KellermanSoftware.NET-Encryption-Library-Core.dll

using System.IO;

namespace ExternalEncryption.NetEncryptionLibrary
{
  internal interface IPublicKeyEncryption
  {
    bool Encrypt(string inputFile, string outputFile, ICustomCert cert);

    string Encrypt(string inputString, ICustomCert cert);

    MemoryStream Encrypt(MemoryStream memStream, ICustomCert cert);

    bool Decrypt(string inputFile, string outputFile, ICustomCert cert);

    string Decrypt(string inputString, ICustomCert cert);

    MemoryStream Decrypt(MemoryStream memStream, ICustomCert cert);
  }
}
