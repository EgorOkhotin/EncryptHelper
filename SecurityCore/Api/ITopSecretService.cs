using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.Api
{
    public interface ITopSecretService
    {
        void SetKey1(SecureString key);
        void SetKey2(SecureString key);
        void SetKey3(SecureString key3);

        byte[] Encrypt(byte[] message);
        byte[] Decrypt(byte[] message);
    }
}
