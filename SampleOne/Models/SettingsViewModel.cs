﻿using SampleOne.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace SampleOne.Models
{
    [Serializable]
    public class SettingsViewModel
    {
        [Required]
        public int PasswordsCount { get; set; }

        [NotEmptyPassword]
        public string[] Passwords { get; set; }
    }
}
