using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using SecurityCore.CryptographyProvider;
using SecurityCore.RNG;
using System.Linq;
using System.Security.Cryptography;

namespace SecurityCore.Keys
{
    class KeyServiceProvider : IKeyService
    {
        IKeyStorage _storage;
        IHashProvider _hash;
        RNGManager _rng;

        public KeyServiceProvider(IKeyStorage keyStorage, IHashProvider provider)
        {
            _storage = keyStorage;
            _hash = provider;
            _rng = new RNGManager();
        }

        public string AddKey(SecureString key)
        {
            var handleResult = HandleKey(key);
            var hash = handleResult.Item1;
            var keyBytes = handleResult.Item2;

            if (!_storage.IsExist(hash))
                _storage.AddKey(hash, keyBytes);
            else throw new ArgumentException($"Already used key! Hash: {hash}");

            return hash;
        }

        public string AddNoTrackKey(SecureString password)
        {
            var handleResult = HandleKey(password);
            var hash = handleResult.Item1;
            var keyBytes = handleResult.Item2;

            if (!_storage.IsExist(hash))
                _storage.AddKey(hash, keyBytes, false);
            else throw new ArgumentException("Already used key!");

            return hash;
        }

        public void Dispose()
        {
            //save keys in storage
            //throw new NotImplementedException();
        }

        public byte[] GetKey(string keyHash)
        {
            if (_storage.IsExist(keyHash))
                return _storage.GetKey(keyHash);
            else throw new ArgumentException("Key not exist in storage");
            //throw new NotImplementedException();
        }

        private Tuple<string, byte[]> HandleKey(SecureString password)
        {
            var keyBytes = password.GetBytes();

            keyBytes = new SHA512Managed().ComputeHash(keyBytes);

            string hash = _hash.Hash(keyBytes);

            return new Tuple<string, byte[]>(hash, keyBytes);
        }

        
    }
}
