using System;
using SecurityCore;
using SecurityCore.Api;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace EncryptHelper
{
    class ProtectedCore : ITransformCore
    {
        IProtectedService _service;
        readonly SecurityCoreProvider _provider;

        public ProtectedCore(SecurityCoreProvider provider)
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
            SecureString pass = new SecureString();
            for(int i=0; i<passwords.Length; i++)
            {
                pass.AppendChar(passwords[i]);
            }
            _service = _provider.GetProtectedService(pass);
        }
    }
}
