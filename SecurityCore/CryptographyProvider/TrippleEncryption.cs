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
        ICryptographyAlgorithm _aes, _twofish, _serpent;
        IKeyService _keyService;

        string _aesKeyHash;
        string _twofishKeyHash;
        string _serpentKeyHash;

        RNGManager _rng;

        public TrippleEncryption(IKeyService service, params CryptoPair[] pairs)
        {
            InitializeAes(pairs[0]);
            InitializeSerpent(pairs[1]);
            InitializeTwofish(pairs[2]);
            _rng = new RNGManager();
            _keyService = service;
        }

        public override byte[] Encrypt(byte[] message)
        {
            var iv = TransformingUtil.GetEmptyIv();
            _rng.GetBytes(iv);
             message = TransformingUtil.AlignMessage(message);

            var result = _twofish.Encrypt(message, GetKey(_twofishKeyHash), iv);
            result = _aes.Encrypt(result, GetKey(_aesKeyHash), iv);
            result = _serpent.Encrypt(result, GetKey(_serpentKeyHash), iv);
            result = iv.Concat(result).ToArray();

            return result;
        }

        public override byte[] Decrypt(byte[] message)
        {
            var tuple = TransformingUtil.GetIv(message);
            var iv = tuple.Item1;
            message = tuple.Item2;

            var result = _serpent.Decrypt(message, GetKey(_serpentKeyHash), iv);
            result = _aes.Decrypt(result, GetKey(_aesKeyHash), iv);
            result = _twofish.Decrypt(result, GetKey(_twofishKeyHash), iv);

            result = TransformingUtil.UnAlignMessage(result);

            return result;
        }

        private byte[] GetKey(string name)
        {
            return _keyService.GetKey(name);
        }

        private void InitializeAes(CryptoPair pair)
        {
            _aes = pair.Algorithm;
            _aesKeyHash = pair.Hash;
        }

        private void InitializeSerpent(CryptoPair pair)
        {
            _serpent = pair.Algorithm;
            _serpentKeyHash = pair.Hash;
        }

        private void InitializeTwofish(CryptoPair pair)
        {
            _twofish = pair.Algorithm;
            _twofishKeyHash = pair.Hash;
        }
    }
}
