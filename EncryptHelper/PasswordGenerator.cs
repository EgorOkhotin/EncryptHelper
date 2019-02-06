using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace EncryptHelper
{
    public class PasswordGenerator
    {
        RNGCryptoServiceProvider _rng;
        public PasswordGenerator()
        {
            _rng = new RNGCryptoServiceProvider();
        }

        public string GeneratePassword(int charCount)
        {
            var buffer = new byte[256];
            _rng.GetBytes(buffer);
            string base64 = Convert.ToBase64String(buffer);
            var result = base64.Substring(0, charCount);
            return result;
        }
    }
}
