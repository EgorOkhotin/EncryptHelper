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
        readonly IKeyAdder _keyAdder;
        public ProtectedProvider(ICryptographyProvider provider, IKeyAdder keyAdder)
        {
            _provider = provider;
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
            var hash = _keyAdder.AddNoTrackKey(key);
            _provider.SetKeys(new CryptoPair(null, hash));
        }
    }
}
