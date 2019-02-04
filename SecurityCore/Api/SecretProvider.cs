using SecurityCore.CryptographyProvider;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace SecurityCore.Api
{
    class SecretProvider : ISecretService
    {
        readonly ICryptographyProvider _provider;

        public SecretProvider(ICryptographyProvider provider)
        {
            this._provider = provider;
        }

        public byte[] Decrypt(byte[] message)
        {
            return _provider.Decrypt(message);
        }

        public byte[] Encrypt(byte[] message)
        {
            return _provider.Encrypt(message);
        }

        public void SetKey(SecureString key)
        {
            throw new NotImplementedException();
        }
    }
}
