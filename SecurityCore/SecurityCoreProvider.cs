using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using SecurityCore.Api;

namespace SecurityCore
{
    public class SecurityCoreProvider
    {
        IServiceFactory _factory;
        public SecurityCoreProvider()
        {
            _factory = new Core();
        }

        bool _isInit = false;
        public void Initialize(SecureString password)
        {
            if(!_isInit)
            {
                Core.Initialize(password);
                _isInit = true;
            }
        }

        public IProtectedService GetProtectedService(SecureString pass) => _factory.GetProtectedServiceProvider(pass);
        public ISecretService GetSecretService(SecureString pass) => _factory.GetSecretServiceProvider(pass);
        public ITopSecretService GetTopSecretService(params SecureString[] pass) => _factory.GetTopSecretServiceProvider(pass);
        public IDiplomaticService GetDiplomaticService(string path) => _factory.GetDiplomaticServiceProvider();

        public void EmergencyDelete()
        {
            Core.DropAllData();
        }
    }
}
