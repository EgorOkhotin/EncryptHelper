using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using ElectronNET;
using ElectronNET.API;

namespace EncryptHelper
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                BuildWebHost(args).Run();
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            return WebHost.CreateDefaultBuilder(args)
                .UseElectron(args)
                .UseStartup<Startup>()
                .Build();
        }

    }
}
