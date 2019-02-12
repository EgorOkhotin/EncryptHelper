using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.Api
{
    public interface ITopSecretService
    {
        void SetKeys(SecureString[] keys);

        byte[] Encrypt(byte[] message);
        byte[] Decrypt(byte[] message);
    }
}
