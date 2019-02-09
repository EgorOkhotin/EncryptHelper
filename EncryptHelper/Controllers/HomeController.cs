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
        static SecurityCoreProvider _provider;
        static ITransformCore _transformCore;
        static EncryptionInfo _info;
        static string _direction;

        static HomeController()
        {
            _provider = new SecurityCoreProvider();
            _info = new EncryptionInfo();
            
        }
        public HomeController()
        {
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }
        [HttpGet]
        public IActionResult Initialization()
        {
            ViewBag.Direction = "front";
            return View();
        }

        public IActionResult InitializationError(string errorMessage)
        {
            ViewBag.Direction = "front";
            ViewBag.Error = errorMessage;
            return View("Initialization");
        }

        [HttpGet]
        public IActionResult Chose()
        {
            ViewData["Message"] = "Your contact page.";
            ViewBag.Direction = _direction;
            return View();
        }

        [HttpPost]
        public async Task<RedirectToActionResult> Settings(SettingsViewModel model)
        {

            await Task.Delay(DELAY);
            if (ModelState.IsValid)
            {
                _info.PasswordsCount = model.PasswordsCount;
                _info.Passwords = model.Passwords;
                return RedirectToAction("GoToEncryption");
            }
            else return RedirectToAction("Error");
        }

        [HttpGet]
        public IActionResult Settings(int? passwordsCount)
        {
            if (passwordsCount > 0)
            {
                var model = new SettingsViewModel();
                model.PasswordsCount = passwordsCount.Value;
                model.Passwords = new string[model.PasswordsCount];
                var view = View(model);
                ViewBag.Direction = _direction;
                return View(model);
            }
            else return Error();
        }
        [HttpGet]
        public IActionResult Encryption()
        {
            InitializeTransformCore(_info);
            _transformCore = _info.EncryptProvider;
            ViewBag.Direction = _direction;
            return View(new Encryption());
        }
        [HttpPost]
        public string CryptoChangeText(Encryption model)
        {
            model.Text = TransformText(model.Text, model.Direction);

            return model.Text;
        }

        [HttpPost]
        public string TransformText(string text, string direction)
        {
            if ((text != null) && (direction != null))
            {
                if(IsValidDirection(direction))
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

        public RedirectToActionResult GoToEncryption()
        {
            return RedirectToAction("Encryption");
        }

        public async Task<RedirectToActionResult> InitializeAsync(InitializationViewModel model)
        {
            if(model.MasterPassword == null || model.MasterPassword=="")
            {
                return RedirectToAction("InitializationError", new { errorMessage = "IncorrectPassword"});
            }
            _provider.Initialize(GetBasePassword(model.MasterPassword));
            return await GoToChoseAsync();
        }

        [HttpGet]
        public async Task<RedirectToActionResult> GoToChoseAsync()
        {
            await Task.Delay(DELAY);
            _direction = "front";
            return RedirectToAction("Chose");
        }

        [HttpGet]
        public async Task<RedirectToActionResult> BackToChoseAsync()
        {
            await Task.Delay(DELAY);
            _direction = "back";
            return RedirectToAction("Chose");
        }
        [HttpGet]
        public async Task<RedirectToActionResult> GoToSettingsAsync(int? selectedTypeNumber)
        {
            await Task.Delay(DELAY);
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
            _direction = "front";
            return RedirectToAction("Settings", "Home", new { passwordsCount = passCount});
        }

        [HttpGet]
        private async Task<RedirectToActionResult> BackToSettingsAsync(int? selectedTypeNumber)
        {
            await Task.Delay(DELAY);
            int passCount = TempData.Get<EncryptionInfo>("EncryptionInfo").PasswordsCount;
            _direction = "back";
            return RedirectToAction("Settings", "Home", new { passwordsCount = passCount });
        }

        [HttpGet]
        public IActionResult MainLogo()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

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
