using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SampleOne.Models;

namespace SampleOne.Controllers
{
    public class HomeController : Controller
    {
        const int DELAY = 10;
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

        //[HttpPost]
        //public IActionResult Encryption()
        //{
        //    return View();
        //}

        [HttpGet]
        public IActionResult Chose()
        {
            ViewData["Message"] = "Your contact page.";
            var direction = TempData.Get<string>("direction");
            ViewData.Add("direction", direction);
            return View();
        }

        [HttpPost]
        public async Task<RedirectToActionResult> Settings(SettingsViewModel model)
        {

            await Task.Delay(DELAY);
            if (ModelState.IsValid)
            {
                EncryptionInfo info = new EncryptionInfo();
                info.PasswordsCount = model.PasswordsCount;
                info.Passwords = model.Passwords;
                TempData.Put("EncryptionInfo", info);
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
                return View(model);
            }
            else return Error();
        }

        public IActionResult Encryption()
        {
            var info = TempData.Get<EncryptionInfo>("EncryptionInfo");
            ViewData.Add("PasswordsCount", info.Passwords.Count());
            return View();
        }

        [HttpGet]
        public string TransformText(string text, string direction)
        {
            if((text != null) && (direction != null))
            {
                if(IsValidDirection(direction))
                {
                    Response.StatusCode = 200;
                    return "Tranformed";
                    //transform text
                    //return text
                }
            }
            Response.StatusCode = 400;
            return "Invalid request";
        }

        public RedirectToActionResult GoToEncryption()
        {
            return RedirectToAction("Encryption");
        }

        [HttpGet]
        public async Task<RedirectToActionResult> GoToChoseAsync()
        {
            await Task.Delay(DELAY);
            TempData.Put("direction", "front");
            return RedirectToAction("Chose");
        }

        [HttpGet]
        public async Task<RedirectToActionResult> BackToChoseAsync()
        {
            await Task.Delay(DELAY);
            TempData.Put("direction", "back");
            return RedirectToAction("Chose");
        }
        [HttpGet]
        public async Task<RedirectToActionResult> GoToSettingsAsync(int? selectedTypeNumber)
        {
            await Task.Delay(DELAY);
            int passCount = -1;
            if (selectedTypeNumber.Value == 1 || selectedTypeNumber.Value == 2) passCount = 1;
            else if(selectedTypeNumber==3) passCount = 3;
            ViewData.Add("direction", "front");
            return RedirectToAction("Settings", "Home", new { passwordsCount = passCount});
        }

        [HttpGet]
        private async Task<RedirectToActionResult> BackToSettingsAsync(int? selectedTypeNumber)
        {
            await Task.Delay(DELAY);
            int passCount = TempData.Get<EncryptionInfo>("EncryptionInfo").PasswordsCount;
            ViewData.Add("direction", "back");
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
                //add random generation
                Response.StatusCode = 200;

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

        
    }
}
