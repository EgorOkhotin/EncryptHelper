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
    class TrippleEncryption : ICryptographyProvider
    {
        ICryptographyAlgorithm _aes, _blowfish, _twofish;
        IKeyService _keyService;

        string _aesKeyHash;
        string _blowfishKeyHash;
        string _twofishKeyHash;

        RNGManager _rng;

        public TrippleEncryption(IKeyService service, params CryptoPair[] pairs)
        {
            InitializeAes(pairs[0]);
            InitializeTwofish(pairs[1]);
            InitializeBlowfish(pairs[2]);
            _rng = new RNGManager();
        }

        public byte[] Encrypt(byte[] message)
        {
            byte[] iv = new byte[Extensions.DATABLOCK_LENGTH];
            _rng.GetBytes(iv);
            var result = _aes.Encrypt(message, GetKey(_aesKeyHash), iv);
            result = _blowfish.Encrypt(result, GetKey(_blowfishKeyHash), iv);
            result = _twofish.Encrypt(result, GetKey(_twofishKeyHash), iv);
            result = iv.Concat(result).ToArray();

            return result;
        }

        public byte[] Decrypt(byte[] message)
        {
            byte[] iv = message.Take(Extensions.DATABLOCK_LENGTH).ToArray();
            message = message.Skip(Extensions.DATABLOCK_LENGTH).ToArray();
            var result = _twofish.Decrypt(message, GetKey(_twofishKeyHash), iv);
            result = _blowfish.Decrypt(result, GetKey(_blowfishKeyHash), iv);
            result = _aes.Decrypt(message, GetKey(_aesKeyHash), iv);

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

        private void InitializeTwofish(CryptoPair pair)
        {
            _twofish = pair.Algorithm;
            _twofishKeyHash = pair.Hash;
        }

        private void InitializeBlowfish(CryptoPair pair)
        {
            _blowfish = pair.Algorithm;
            _blowfishKeyHash = pair.Hash;
        }
    }
}
