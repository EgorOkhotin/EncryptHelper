using SecurityCore.CryptographyProvider;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.Api
{
    class ProtectedProvider : IProtectedService
    {
        readonly ICryptographyProvider _provider;

        public ProtectedProvider(ICryptographyProvider provider)
        {
            _provider = provider;
        }

        public byte[] Decrypt(byte[] message)
        {
            throw new NotImplementedException();
        }

        public byte[] Encrypt(byte[] message)
        {
            throw new NotImplementedException();
        }

        public void SetKey(SecureString key)
        {
            throw new NotImplementedException();
        }
    }
}
