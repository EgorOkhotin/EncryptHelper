using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.Api
{
    public interface IProtectedService
    {
        void SetKey(SecureString key);
        byte[] Encrypt(byte[] message);
        byte[] Decrypt(byte[] message);       
    }
}
