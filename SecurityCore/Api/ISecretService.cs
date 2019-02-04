using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.Api
{
    public interface ISecretService
    {
        void SetKey(SecureString key);
        byte[] Encrypt(byte[] message);
        byte[] Decrypt(byte[] message);
    }
}
