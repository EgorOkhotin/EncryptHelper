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
        string _keyHash;
        readonly IKeyService _keyService;

        public SingleEncryption(CryptoPair pair, IKeyService service)
        {
            _keyService = service;
            _alg = pair.Algorithm;
            _keyHash = pair.Hash;

            BlockSize = _alg.BlockByteSize;
            KeySize = _alg.KeyByteSize;
        }

        public override byte[] Decrypt(byte[] message)
        {
            var tuple = SplitMessage(message);
            byte[] iv = tuple.Item1;
            message = tuple.Item2;

            var result = _alg.Decrypt(message, _keyService.GetKey(_keyHash), iv);

            result = UnAlignMessage(result);

            return result;
        }

        public override byte[] Encrypt(byte[] message)
        {
            var iv = GetIv();

            message = AlignMessage(message);

            var result = _alg.Encrypt(message, _keyService.GetKey(_keyHash), iv);
            result = iv.Concat(result).ToArray();
            return result;
        }

        public override void SetKeys(params CryptoPair[] pairs)
        {
            if(pairs != null)
            {
                if(pairs.Length > 0)
                {
                    if(IsValidKey(pairs[0]))
                        _keyHash = pairs[0].Hash;
                }
            }
        }
    }
}
