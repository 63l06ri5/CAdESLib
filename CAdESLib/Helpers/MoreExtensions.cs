using System;
using System.ComponentModel;
using System.Reflection;

namespace CAdESLib.Helpers
{
    public static class MoreExtensions
    {
        public static string? GetDescription(this Enum? value)
        {
            FieldInfo? fi = value?.GetType().GetField(value.ToString());

            // указываем inherit=true, потому что есть LocalizableDescriptionAttribute
            var attributes = (DescriptionAttribute[]?)fi?.GetCustomAttributes(typeof(DescriptionAttribute), true);
            return attributes?.Length > 0 ? attributes[0].Description : value?.ToString();
        }

    }
}

