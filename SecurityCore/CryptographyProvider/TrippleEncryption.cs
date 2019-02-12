using SecurityCore.CryptographyProvider.Algos;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using System.Linq;
using SecurityCore.RNG;
using SecurityCore.Keys;

namespace SecurityCore.CryptographyProvider
{
    class TrippleEncryption : CryptographyProvider
    {
        readonly ICryptographyAlgorithm _aes, _twofish, _serpent;
        readonly IKeyService _keyService;

        string _aesKeyHash;
        string _twofishKeyHash;
        string _serpentKeyHash;

        public TrippleEncryption(IKeyService service, params CryptoPair[] pairs) :this(pairs)
        {
            _keyService = service;
        }

        private TrippleEncryption(CryptoPair[] pairs)
        {
            var pair = pairs[0];
            _aes = pair.Algorithm;
            _aesKeyHash = pair.Hash;

            pair = pairs[1];
            _serpent = pair.Algorithm;
            _serpentKeyHash = pair.Hash;

            pair = pairs[2];
            _twofish = pair.Algorithm;
            _twofishKeyHash = pair.Hash;

            BlockSize = GetMax(_aes.BlockByteSize, _twofish.BlockByteSize, _serpent.BlockByteSize);
            KeySize = GetMax(_aes.KeyByteSize, _twofish.KeyByteSize, _serpent.KeyByteSize);
        }

        public override byte[] Encrypt(byte[] message)
        {
            var iv = GetIv();
            message = AlignMessage(message);

            var result = _twofish.Encrypt(message, GetKey(_twofishKeyHash), iv);
            result = _aes.Encrypt(result, GetKey(_aesKeyHash), iv);
            result = _serpent.Encrypt(result, GetKey(_serpentKeyHash), iv);
            result = iv.Concat(result).ToArray();

            return result;
        }

        public override byte[] Decrypt(byte[] message)
        {
            var tuple = SplitMessage(message);
            var iv = tuple.Item1;
            message = tuple.Item2;

            var result = _serpent.Decrypt(message, GetKey(_serpentKeyHash), iv);
            result = _aes.Decrypt(result, GetKey(_aesKeyHash), iv);
            result = _twofish.Decrypt(result, GetKey(_twofishKeyHash), iv);

            result = UnAlignMessage(result);

            return result;
        }

        public override void SetKeys(params CryptoPair[] pairs)
        {
            if(pairs != null)
            {
                SetKeys(pairs);
            }
        }

        private byte[] GetKey(string name)
        {
            return _keyService.GetKey(name);
        }

        private void ChangeKeys(params CryptoPair[] pairs)
        {
            if(pairs.Length > 0)
            {
                _aesKeyHash = pairs[0].Hash;
                _twofishKeyHash = pairs[1].Hash;
                _serpentKeyHash = pairs[2].Hash;
            }
            else throw new ArgumentException("Bad pairs count!");
        }
    }
}
