using System;
using System.Collections.Generic;
using System.Text;
using SecurityCore.CryptographyProvider.Algos;
using SecurityCore.Keys;
using SecurityCore.RNG;
using System.Linq;

namespace SecurityCore.CryptographyProvider
{
    class SingleEncryption : ICryptographyProvider
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
        }



        public byte[] Decrypt(byte[] message)
        {
            byte[] iv = message.Take(Extensions.IV_LENGTH).ToArray();
            byte[] chiperText = message.Skip(Extensions.IV_LENGTH).ToArray();
            var result = _alg.Decrypt(chiperText, _keyService.GetKey(_keyHash), iv);
            return result;
        }

        public byte[] Encrypt(byte[] message)
        {
            byte[] iv = new byte[Extensions.DATABLOCK_LENGTH/2];
            _rng.GetBytes(iv);
            var result = _alg.Encrypt(message, _keyService.GetKey(_keyHash), iv);
            result = iv.Concat(result).ToArray();
            return result;
        }
    }
}
