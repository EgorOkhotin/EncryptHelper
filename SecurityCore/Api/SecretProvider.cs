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
        readonly IKeyAdder _keyAdder;
        public SecretProvider(ICryptographyProvider provider, IKeyAdder keyAdder)
        {
            this._provider = provider;
            _keyAdder = keyAdder;
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
            var hash = _keyAdder.AddKey(key);
            _provider.SetKeys(new CryptoPair(null, hash));
        }
    }
}
