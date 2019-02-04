using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using SecurityCore.Api;

namespace SecurityCore
{
    public class SecurityCoreProvider
    {
        bool _isInit = false;
        public void Initialize(SecureString password)
        {
            if(!_isInit)
            {
                Core.Initialize(password);
                _isInit = true;
            }
        }

        public IProtectedService GetProtectedService(SecureString pass) => Core.GetProtectedServiceProvider(pass);
        public ISecretService GetSecretService(SecureString pass) => Core.GetSecretServiceProvider(pass);
        public ITopSecretService GetTopSecretService(params SecureString[] pass) => Core.GetTopSecretServiceProvider(pass);
        public IDiplomaticService GetDiplomaticService(string path) => Core.GetDiplomaticServiceProvider();
    }
}
