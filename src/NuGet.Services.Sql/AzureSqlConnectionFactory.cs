// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using NuGet.Services.KeyVault;

namespace NuGet.Services.Sql
{
    public class AzureSqlConnectionFactory : ISqlConnectionFactory
    {
        private const string AzureSqlResourceId = "https://database.windows.net/";

        private const int RetryIntervalInMilliseconds = 250;

        public AzureSqlConnectionStringBuilder ConnectionStringBuilder { get; }

        public ISecretInjector SecretInjector { get; }

        public ISecretReader SecretReader {
            get
            {
                return SecretInjector.SecretReader;
            }
        }

        public AzureSqlConnectionFactory(string connectionString, ISecretInjector secretInjector)
        {
            if (string.IsNullOrEmpty(connectionString))
            {
                throw Exceptions.ArgumentNullOrEmpty(nameof(connectionString));
            }

            ConnectionStringBuilder = new AzureSqlConnectionStringBuilder(connectionString);
            SecretInjector = secretInjector ?? throw new ArgumentNullException(nameof(secretInjector));
        }

        public async Task<SqlConnection> CreateAsync()
        {
            try
            {
                return await ConnectAsync();
            }
            catch (Exception e) when (IsAdalException(e))
            {
                await Task.Delay(RetryIntervalInMilliseconds);

                RefreshSecrets();

                return await ConnectAsync();
            }
        }

        protected virtual async Task<SqlConnection> ConnectAsync()
        {
            var connectionString = await SecretInjector.InjectAsync(ConnectionStringBuilder.ConnectionString);
            var connection = new SqlConnection(connectionString);

            if (!string.IsNullOrWhiteSpace(ConnectionStringBuilder.AadAuthority))
            {
                connection.AccessToken = await GetAccessTokenAsync();
            }

            await OpenConnectionAsync(connection);

            return connection;
        }

        private async Task<string> GetAccessTokenAsync()
        {
            var certificate = await GetCertificateSecretAsync(ConnectionStringBuilder.AadCertificate);

            var authenticationContext = new AuthenticationContext(ConnectionStringBuilder.AadAuthority);
            var clientAssertion = new ClientAssertionCertificate(ConnectionStringBuilder.AadClientId, certificate);

            var result = await authenticationContext.AcquireTokenAsync(AzureSqlResourceId, clientAssertion, ConnectionStringBuilder.AadSendX5c);
            return result.AccessToken;
        }

        protected virtual Task OpenConnectionAsync(SqlConnection sqlConnection)
        {
            return sqlConnection.OpenAsync();
        }

        private async Task<X509Certificate2> GetCertificateSecretAsync(string input)
        {
            var certSecret = GetSecretName(ConnectionStringBuilder.AadCertificate);
            var secret = await SecretReader.GetSecretAsync(certSecret);
            return new X509Certificate2(Convert.FromBase64String(secret), string.Empty);
        }

        private void RefreshSecrets()
        {
            var cachingSecretReader = SecretReader as ICachingSecretReader;   
            if (cachingSecretReader != null)
            {
                foreach (var secret in SecretInjector.GetSecretNames(ConnectionStringBuilder.ConnectionString))
                {
                    cachingSecretReader.RefreshSecret(secret);
                }

                var certSecret = GetSecretName(ConnectionStringBuilder.AadCertificate);
                if (!string.IsNullOrEmpty(certSecret))
                {
                    cachingSecretReader.RefreshSecret(certSecret);
                }
            }
        }

        private string GetSecretName(string input)
        {
            return SecretInjector.GetSecretNames(input).SingleOrDefault();
        }

        private static bool IsAdalException(Exception e)
        {
            return (e is AdalException) ? true
                : (e.InnerException != null) ? IsAdalException(e.InnerException) : false;
        }
    }
}
