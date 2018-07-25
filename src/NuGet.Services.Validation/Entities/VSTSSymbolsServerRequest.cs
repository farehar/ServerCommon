﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace NuGet.Services.Validation
{
    public class VSTSSymbolsServerRequest
    {
        /// <summary>
        /// The key of the symbols package.
        /// </summary>
        public int SymbolsKey { get; set; }

        /// <summary>
        /// The request name used for ingestion in VSTS.
        /// </summary>
        public string RequestName { get; set; }

        /// <summary>
        /// The status of the VSTS request to ingest symbols.
        /// </summary>
        public SymbolsPackageIngestRequestStatus RequestStatusKey { get; set; }

        /// <summary>
        /// Timestamp when this symbol was created.
        /// </summary>
        [DatabaseGenerated(DatabaseGeneratedOption.Computed)]
        public DateTime Created { get; set; }

        /// <summary>
        /// Used for optimistic concurrency when updating the status.
        /// </summary>
        public byte[] RowVersion { get; set; }
    }
}
