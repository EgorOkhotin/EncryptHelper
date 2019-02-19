using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using EncryptHelper.Models;
using SecurityCore.Api;
using SecurityCore;
using System.Security;
using System.IO;
using Newtonsoft.Json;

namespace EncryptHelper.Controllers
{
    public class HomeController : Controller
    {
        const int DELAY = 10;
        static readonly SecurityCoreProvider _provider;
        static ITransformCore _transformCore;
        static EncryptionInfo _info;

        static HomeController()
        {
            _provider = new SecurityCoreProvider();
            _info = new EncryptionInfo();
            
        }

        public HomeController()
        {
        }
        [ResponseCache(NoStore =true, Location =ResponseCacheLocation.None)]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet("Home/EncryptHelper")]
        [ResponseCache(NoStore =true, Location =ResponseCacheLocation.None)]
        public IActionResult Initialization()
        {
            ViewData["Title"] = "EncryptHelper";
            return View();
        }

        [HttpPost]
        public IActionResult Initialization(InitializationViewModel model)
        {
            if (model.MasterPassword == null || model.MasterPassword == "")
            {
                ViewBag.Error = "IncorrectPassword";
                Response.StatusCode = 400;
                
                return PartialView();
            }
            _provider.Initialize(GetBasePassword(model.MasterPassword));
            return Chose();
        }

        [HttpGet]
        public IActionResult Chose()
        {
            return PartialView("Chose");
        }

        [HttpPost]
        public IActionResult Chose(int? selectedTypeNumber)
        {
            int passCount = -1;
            if (selectedTypeNumber.Value == 1)
            {
                passCount = 1;
                _info.Type = TransformType.Protected;
            }
            else if (selectedTypeNumber.Value == 2)
            {
                passCount = 1;
                _info.Type = TransformType.Secret;
            }
            else if (selectedTypeNumber == 3)
            {
                passCount = 3;
                _info.Type = TransformType.TopSecret;
            }
            else return Error("Selected type is invalid");
            
            return Settings(passCount);
        }

        [HttpGet]
        public IActionResult Settings(int? passwordsCount)
        {
            if (passwordsCount.HasValue && passwordsCount > 0)
            {
                var model = new SettingsViewModel();
                model.PasswordsCount = passwordsCount.Value;
                model.Passwords = new string[model.PasswordsCount];
                var view = View(model);
                return PartialView("Settings", model);
            }
            else return Error("Bad passwords count");
        }

        [HttpPost]
        public IActionResult Settings(SettingsViewModel model)
        {
            if (ModelState.IsValid)
            {
                _info.Passwords = model.Passwords;
                return Encryption();
            }
            else return Error("Password(s) are invalid");
        }

        [HttpGet]
        public IActionResult Encryption()
        {
            InitializeTransformCore(_info);
            _transformCore = _info.EncryptProvider;
            return PartialView("Encryption",new Encryption());
        }

        [HttpPost]
        public string Encryption(Encryption model)
        {
            model.Text = TransformText(model.Text, model.Direction);            
            return model.Text;
        }

        [HttpPost]
        public void EmergencyDeleteData()
        {
            _provider.EmergencyDelete();
        }

        [HttpGet]
        public IActionResult MainLogo()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return Error("Empty error message");
        }

        private IActionResult Error(string message)
        {
            ViewBag.Error = message;
            Response.StatusCode = 400;
            return View();
        }

        //API
        [HttpGet]
        public string GetRandomPassword(int? charCount)
        {
            if (charCount.HasValue && charCount.Value>3)
            {
                string password = "samplePass";
                //TODO add random pass generation
                Response.StatusCode = 200;
                password = (new PasswordGenerator()).GeneratePassword(charCount.Value);
                return password;
            }
            else
            {
                Response.StatusCode = 400;
                return "Invalid count of characters";
            }
        }
        //
        private string TransformText(string text, string direction)
        {
            if ((text != null) && (direction != null))
            {
                if (IsValidDirection(direction))
                {
                    Response.StatusCode = 200;
                    var provider = TakeTransformProvider();
                    if (direction == "encrypt")
                    {
                        return provider.Encrypt(text);
                    }
                    else
                    {
                        return provider.Decrypt(text);
                    }
                }
            }
            Response.StatusCode = 400;
            return "Invalid request";
        }

        private static bool IsValidDirection(string direction)
        {
            direction = direction.ToUpper();
            return (direction == "ENCRYPT" || direction == "DECRYPT");
        }

        private void InitializeTransformCore(EncryptionInfo info)
        {
            if(info.Type == TransformType.Protected)
            {
                info.EncryptProvider = GetProtectedCore(info);
            }
            else if(info.Type == TransformType.Secret)
            {
                info.EncryptProvider = GetSecretCore(info);
            }
            else if(info.Type == TransformType.TopSecret)
            {
                info.EncryptProvider = GetTopSecretCore(info);
            }
            else
            {
                //add error
            }
        }

        private ITransformCore TakeTransformProvider()
        {
            return _transformCore;
        }

        private ITransformCore GetProtectedCore(EncryptionInfo info)
        {
            var core = new ProtectedCore(_provider);
            core.SetKeys(info.Passwords[0]);
            return core;
        }

        private ITransformCore GetSecretCore(EncryptionInfo info)
        {
            var core = new SecretCore(_provider);
            core.SetKeys(info.Passwords[0]);
            return core;
        }

        private ITransformCore GetTopSecretCore(EncryptionInfo info)
        {
            var core = new TopSecretCore(_provider);
            string passwords = info.Passwords[0] + "\n";
            passwords += info.Passwords[1] + "\n";
            passwords += info.Passwords[2];
            core.SetKeys(passwords);
            return core;
        }

        private static SecureString GetBasePassword(string password)
        {
            var result = new SecureString();
            foreach(var c in password)
            {
                result.AppendChar(c);
            }
            return result;
        }
    }
}
