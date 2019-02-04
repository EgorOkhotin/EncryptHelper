using SecurityCore;
using SecurityCore.Api;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace SampleOne
{
    class TopSecretCore : ITransformCore
    {
        readonly SecurityCoreProvider _provider;
        ITopSecretService _service;

        public TopSecretCore(SecurityCoreProvider provider)
        {
            _provider = provider;
        }

        public string Decrypt(string message)
        {
            var bytes = Convert.FromBase64String(message);
            bytes = _service.Decrypt(bytes);
            var result = Encoding.Unicode.GetString(bytes);
            return result;
        }

        public string Encrypt(string message)
        {
            var bytes = Encoding.Unicode.GetBytes(message);
            bytes = _service.Encrypt(bytes);
            var result = Convert.ToBase64String(bytes);
            return result;
        }

        public void SetKeys(string passwords)
        {
            var pass = passwords.Split('\n');
            if (pass.Length < 3) throw new ArgumentException("Need more passwords");

            SecureString firstKey = new SecureString();
            for (int i = 0; i < pass[0].Length; i++)
                firstKey.AppendChar(pass[0][i]);

            SecureString secondKey = new SecureString();
            for (int i = 0; i < pass[1].Length; i++)
                secondKey.AppendChar(pass[1][i]);

            SecureString thirdKey = new SecureString();
            for (int i = 0; i < pass[2].Length; i++)
                thirdKey.AppendChar(pass[2][i]);

            _service = _provider.GetTopSecretService(firstKey, secondKey, thirdKey);
        }
    }
}
