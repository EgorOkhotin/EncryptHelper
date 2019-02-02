using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using SampleOne.Models;

namespace SampleOne.Controllers
{
    public class HomeController : Controller
    {
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
        public IActionResult Chose()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        //[HttpGet("Settings/")]
        //public IActionResult Settings()
        //{
        //    var model = new SettingsViewModel();
        //    model.Passwords = new string[0];
        //    model.PasswordsCount = 0;
        //    return View();
        //}

        [HttpPost]
        public async Task<RedirectToActionResult> Settings(SettingsViewModel model)
        {

            await Task.Delay(900);
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

        public RedirectToActionResult GoToEncryption()
        {
            return RedirectToAction("Encryption");
        }

        [HttpGet]
        public async Task<RedirectToActionResult> GoToChoseAsync()
        {
            await Task.Delay(900);
            return RedirectToAction("Chose");
        }

        [HttpGet]
        public async Task<RedirectToActionResult> GoToSettingsAsync(int? selectedTypeNumber)
        {
            await Task.Delay(900);
            int passCount = -1;
            if (selectedTypeNumber.Value == 1 || selectedTypeNumber.Value == 2) passCount = 1;
            else if(selectedTypeNumber==3) passCount = 3;
            return RedirectToAction("Settings", "Home", new { passwordsCount = passCount});
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
    }
}
