﻿// Copyright (c) .NET Foundation. All rights reserved. 
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information. 

using System.Collections.Generic;
using NuGet.Services.KeyVault;

namespace NuGet.Services.Configuration
{
    public interface ISecretDictionary : IDictionary<string, string>
    {
        ISecretInjector SecretInjector { get; }
    }
}
