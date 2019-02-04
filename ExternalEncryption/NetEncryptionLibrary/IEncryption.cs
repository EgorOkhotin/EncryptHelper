// Decompiled with JetBrains decompiler
// Type: KellermanSoftware.NetEncryptionLibrary.IEncryption
// Assembly: KellermanSoftware.NET-Encryption-Library-Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: F7015153-C9B6-47CF-A891-816AAF547510
// Assembly location: D:\Temp\KellermanSoftware.NET-Encryption-Library-Core.dll

using System.IO;
using System.Text;

namespace ExternalEncryption.NetEncryptionLibrary
{
  public interface IEncryption
  {
    int KeySize { get; set; }

    Encoding EncodingMethod { get; set; }

    byte[] EncryptBytes(string key, byte[] dataToEncrypt);

    byte[] DecryptBytes(string key, byte[] dataToDecrypt);

    string EncryptString(string key, string inputString, bool writeEncryptionPrefix);

    string DecryptString(string key, string inputString);

    bool EncryptStream(string key, Stream inputStream, Stream outputStream, bool useBase64);

    bool DecryptStream(string key, Stream inputStream, Stream outputStream, bool useBase64);

    bool EncryptFile(string key, string inputFilePath, string outputFilePath, bool useBase64);

    bool DecryptFile(string key, string inputFilePath, string outputFilePath, bool useBase64);
  }
}
