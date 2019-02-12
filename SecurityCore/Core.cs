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
    internal class Core : IServiceFactory, IKeyAdder
    {
        static IDataCleaner _dataManager;
        static IKeyBase _db;
        static IKeyService _keyService;
        static bool _isInit;

        static Core()
        {
            _isInit = false;
        }

        public ISecretService GetSecretServiceProvider(SecureString password)
        {
            var hash = AddKey(password);
            CryptoPair p = new CryptoPair(new AES(), hash);
            ICryptographyProvider provdier = new SingleEncryption(p, _keyService);
            ISecretService service = new SecretProvider(provdier, this);
            return service;
        }

        public IDiplomaticService GetDiplomaticServiceProvider()
        {
            throw new NotImplementedException();
        }

        public IProtectedService GetProtectedServiceProvider(SecureString pass)
        {
            var hash = AddNoTrackKey(pass);
            CryptoPair p = new CryptoPair(new AES(), hash);
            ICryptographyProvider provider = new SingleEncryption(p, _keyService);
            IProtectedService service = new ProtectedProvider(provider, this);
            return service;
        }

        public ITopSecretService GetTopSecretServiceProvider(params SecureString[] passwords)
        {
            if (passwords.Length < 3) throw new ArgumentException("Need more passwords");
            var hash1 = AddKey(passwords[0]);
            var hash2 = AddKey(passwords[1]);
            var hash3 = AddKey(passwords[2]);
            var pairs = new CryptoPair[]
            {
                new CryptoPair(new AES(), hash1),
                new CryptoPair(new Serpent(), hash2),
                new CryptoPair(new Twofish(), hash3)
            };

            ICryptographyProvider provider = new TrippleEncryption(_keyService, pairs);
            ITopSecretService service = new TopSecretProvider(provider, this);
            return service;
        }

        internal static void DropAllData()
        {
            _isInit = false;
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

        public string AddKey(SecureString key)
        {
            return _keyService.AddKey(key);
        }

        public string AddNoTrackKey(SecureString key)
        {
            return _keyService.AddNoTrackKey(key);
        }

        private string AddKey(SecureString key, bool isTrackKey)
        {
            if(isTrackKey)
            {
                return _keyService.AddKey(key);
            }
            else
            {
                return _keyService.AddNoTrackKey(key);
            }
        }
    }
}
