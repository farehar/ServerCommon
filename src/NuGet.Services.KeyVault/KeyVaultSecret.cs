﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NuGet.Services.KeyVault
{
    public class KeyVaultSecret : ISecret
    {
        public KeyVaultSecret(string name, string value, DateTime? expiryDate)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            Name = name;
            Value = value;
            Expiration = expiryDate;
        }

        public string Name { get; }

        public string Value { get; }

        public DateTime? Expiration { get; }

    }
}
