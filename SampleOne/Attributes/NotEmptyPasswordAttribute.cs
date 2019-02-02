using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using SampleOne.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace SampleOne.Attributes
{
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = false)]
    public class NotEmptyPasswordAttribute : ValidationAttribute, IClientModelValidator
    {
        public NotEmptyPasswordAttribute()
        {
        }
        
        public void AddValidation(ClientModelValidationContext context)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            MergeAttribute(context.Attributes, "data-val", "true");
            var errorMessage = FormatErrorMessage(context.ModelMetadata.GetDisplayName());
            MergeAttribute(context.Attributes, "data-val-cannotbered", errorMessage);
            //if (context == null) throw new ArgumentNullException(nameof(context));
            //CheckForLocalizer(context);
            //var errorMessage = GetErrorMessage(context.ModelMetadata.GetDisplayName());
            //MergeAttribute(context.Attributes, "data-val", "true");
            //MergeAttribute(context.Attributes, "data-val-enforcetrue", errorMessage);
            //MergeAttribute(context.Attributes, "data-val-other", "#" + OtherProperty);
            //throw new NotImplementedException();
        }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (validationContext == null) throw new ArgumentNullException(nameof(validationContext));
            string[] passwords = ((SettingsViewModel)validationContext.ObjectInstance).Passwords;
            bool checkResult = true;
            foreach (var p in passwords)
                if (p == null || p == "" || p.Length <= 3)
                {
                    checkResult = false;
                    break;
                }
            if (checkResult) return ValidationResult.Success;
            else return new ValidationResult("One or more passwords was empty!");
        }

        private bool MergeAttribute(IDictionary<string, string> attributes, string key, string value)
        {
            if (attributes.ContainsKey(key))
            {
                return false;
            }
            attributes.Add(key, value);
            return true;
        }
    }
}
