using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using SecurityCore.Api;
using SecurityCore.Keys;
using SecurityCore.Loader;
using SecurityCore.CryptographyProvider;
using SecurityCore.CryptographyProvider.Algos;

namespace SecurityCore
{
    static class Core
    {
        static IDataCleaner _dataManager;
        static IKeyBase _db;
        static IKeyService _keyService;
        static bool _isInit;

        static Core()
        {
            _isInit = false;
        }

        internal static ISecretService GetSecretServiceProvider(SecureString password)
        {
            var hash = _keyService.AddKey(password);
            CryptoPair p = new CryptoPair(new AES(), hash);
            ICryptographyProvider provdier = new SingleEncryption(p, _keyService);
            ISecretService service = new SecretProvider(provdier);
            return service;
        }

        internal static IDiplomaticService GetDiplomaticServiceProvider()
        {
            throw new NotImplementedException();
        }

        internal static IProtectedService GetProtectedServiceProvider(SecureString pass)
        {
            var hash = _keyService.AddNoTrackKey(pass);
            CryptoPair p = new CryptoPair(new AES(), hash);
            ICryptographyProvider provider = new SingleEncryption(p, _keyService);
            IProtectedService service = new ProtectedProvider(provider);
            return service;
        }

        internal static ITopSecretService GetTopSecretServiceProvider(params SecureString[] passwords )
        {
            if (passwords.Length < 3) throw new ArgumentException("Need more passwords");
            var hash1 = _keyService.AddKey(passwords[0]);
            var hash2 = _keyService.AddKey(passwords[1]);
            var hash3 = _keyService.AddKey(passwords[2]);
            var pairs = new CryptoPair[]
            {
                new CryptoPair(new AES(), hash1),
                new CryptoPair(new Serpent(), hash2),
                new CryptoPair(new Twofish(), hash3)
            };

            ICryptographyProvider provider = new TrippleEncryption(_keyService, pairs);
            ITopSecretService service = new TopSecretProvider(provider);
            return service;
        }

        internal static void DropAllData()
        {
            _dataManager.ImmediatelyDataDelete();
        }

        internal static void Initialize(SecureString pass, SecureString filePass = null)
        {
            if(!_isInit)
            {
                KeyLoader db = new KeyLoader(pass);
                _db = db;
                KeyCollector collector = KeyCollector.GetInstance(db);
                _dataManager = DataManager.GetInstance(collector);
                _keyService = new KeyServiceProvider(collector, new HashProvider());
            }
        }
    }
}
