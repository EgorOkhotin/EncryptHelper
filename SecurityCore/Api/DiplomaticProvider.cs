using SecurityCore.CryptographyProvider;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityCore.Api
{
    class DiplomaticProvider : IDiplomaticService
    {
        readonly ICryptographyProvider _provider;

        public DiplomaticProvider(ICryptographyProvider provider)
        {
            _provider = provider;
        }

        public byte[] Decrypt(byte[] message, string filePath)
        {
            throw new NotImplementedException();
        }

        public byte[] Encrypt(byte[] message, string filePath)
        {
            throw new NotImplementedException();
        }
    }
}
