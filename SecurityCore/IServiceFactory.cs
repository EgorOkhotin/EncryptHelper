using System;
using System.Security;
using SecurityCore.Api;

namespace SecurityCore
{
    internal interface IServiceFactory
    {
        ISecretService GetSecretServiceProvider(SecureString password);
        IDiplomaticService GetDiplomaticServiceProvider();
        IProtectedService GetProtectedServiceProvider(SecureString pass);
        ITopSecretService GetTopSecretServiceProvider(params SecureString[] passwords);
    }
}