using SecurityCore.CryptographyProvider;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.Api
{
    class TopSecretProvider : ITopSecretService
    {
        readonly ICryptographyProvider _provider;

        public TopSecretProvider(ICryptographyProvider provider)
        {
            _provider = provider;
        }

        public byte[] Decrypt(byte[] message)
        {
            return _provider.Decrypt(message);
        }

        public byte[] Encrypt(byte[] message)
        {
            return _provider.Encrypt(message);
        }

        public void SetKey1(SecureString key)
        {
            throw new NotImplementedException();
        }

        public void SetKey2(SecureString key)
        {
            throw new NotImplementedException();
        }

        public void SetKey3(SecureString key3)
        {
            throw new NotImplementedException();
        }
    }
}
