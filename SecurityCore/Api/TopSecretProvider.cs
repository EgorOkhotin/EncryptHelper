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
        readonly IKeyAdder _keyAdder;
        public TopSecretProvider(ICryptographyProvider provider, IKeyAdder keyAdder)
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

        public void SetKeys(SecureString[] keys)
        {
            if(keys==null) throw new ArgumentNullException("Keys were null");
            var hashes = new List<CryptoPair>();
            foreach(var p in keys)
            {
                hashes.Add(new CryptoPair(null,_keyAdder.AddKey(p)));
            }
            _provider.SetKeys(hashes.ToArray());
        }
    }
}
