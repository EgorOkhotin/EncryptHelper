using System;
using System.Collections.Generic;
using System.Text;
using SecurityCore.CryptographyProvider.Algos;
using SecurityCore.Keys;
using SecurityCore.RNG;
using System.Linq;

namespace SecurityCore.CryptographyProvider
{
    class SingleEncryption : CryptographyProvider
    {
        readonly ICryptographyAlgorithm _alg;
        readonly string _keyHash;
        readonly IKeyService _keyService;
        readonly RNGManager _rng;

        public SingleEncryption(CryptoPair pair, IKeyService service)
        {
            _keyService = service;
            _rng = new RNGManager();
            _alg = pair.Algorithm;
            _keyHash = pair.Hash;
            //KeyHashes.Add(pair.Hash);
        }

        public override byte[] Decrypt(byte[] message)
        {
            var tuple = TransformingUtil.GetIv(message);
            byte[] iv = tuple.Item1;
            message = tuple.Item2;

            var result = _alg.Decrypt(message, _keyService.GetKey(_keyHash), iv);

            result = TransformingUtil.UnAlignMessage(result);

            return result;
        }

        public override byte[] Encrypt(byte[] message)
        {
            var iv = TransformingUtil.GetEmptyIv();
            _rng.GetBytes(iv);

            message = TransformingUtil.AlignMessage(message);

            var result = _alg.Encrypt(message, _keyService.GetKey(_keyHash), iv);
            result = iv.Concat(result).ToArray();
            return result;
        }
    }
}
