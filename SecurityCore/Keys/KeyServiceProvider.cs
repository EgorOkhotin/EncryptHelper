using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using SecurityCore.CryptographyProvider;
using SecurityCore.RNG;
using System.Linq;

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
            var middleKey = handleResult.Item3;

            if (!_storage.IsExist(hash))
                _storage.AddKey(hash, keyBytes, middleKey);
            else throw new ArgumentException("Already used key!");

            return hash;
            ////hash primary key and add in collector and check already exist
            //throw new NotImplementedException();
        }

        public string AddNoTrackKey(SecureString password)
        {
            var handleResult = HandleKey(password);
            var hash = handleResult.Item1;
            var keyBytes = handleResult.Item2;
            var middleKey = handleResult.Item3;

            if (!_storage.IsExist(hash))
                _storage.AddKey(hash, keyBytes, middleKey, false);
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

        private Tuple<string, byte[], byte[]> HandleKey(SecureString password)
        {
            var keyBytes = password.GetBytes()
                .Take(Extensions.DATABLOCK_LENGTH)
                .ToArray();

            string hash = _hash.Hash(keyBytes);

            var middleKey = new byte[keyBytes.Length];
            _rng.GetBytes(middleKey);

            return new Tuple<string, byte[], byte[]>(hash, keyBytes, middleKey);
        }

        
    }
}
