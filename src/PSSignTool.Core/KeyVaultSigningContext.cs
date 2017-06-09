﻿using Microsoft.Azure.KeyVault;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenVsixSignTool.Core
{
    /// <summary>
    /// A signing context used for signing packages with Azure Key Vault Keys.
    /// </summary>
    public class KeyVaultSigningContext : ISigningContext
    {
        readonly AzureKeyVaultMaterializedConfiguration configuration;

        /// <summary>
        /// Creates a new siging context.
        /// </summary>
        public KeyVaultSigningContext(AzureKeyVaultMaterializedConfiguration configuration)
        {
            ContextCreationTime = DateTimeOffset.Now;
            this.configuration = configuration;
        }

        /// <summary>
        /// Gets the date and time that this context was created.
        /// </summary>
        public DateTimeOffset ContextCreationTime { get; }

        /// <summary>
        /// Gets the file digest algorithm.
        /// </summary>
        public HashAlgorithmName FileDigestAlgorithmName => configuration.FileDigestAlgorithm;

        /// <summary>
        /// Gets the certificate and public key used to validate the signature.
        /// </summary>
        public X509Certificate2 Certificate => configuration.PublicCertificate;

        /// <summary>
        /// Gets the signature algorithm. Currently, only <see cref="SigningAlgorithm.RSA"/> is supported.
        /// </summary>
        public SigningAlgorithm SignatureAlgorithm { get; } = SigningAlgorithm.RSA;

        public async Task<byte[]> SignDigestAsync(byte[] digest)
        {
            var client = configuration.Client;
            var algorithm = SignatureAlgorithmTranslator.SignatureAlgorithmToJwsAlgId(SignatureAlgorithm, configuration.PkcsDigestAlgorithm);
            var signature = await client.SignAsync(configuration.Key.KeyIdentifier.Identifier, algorithm, digest);
            return signature.Result;
        }

        public Task<bool> VerifyDigestAsync(byte[] digest, byte[] signature)
        {
            using (var publicKey = Certificate.GetRSAPublicKey())
            {
                return Task.FromResult(publicKey.VerifyHash(digest, signature, configuration.PkcsDigestAlgorithm, RSASignaturePadding.Pkcs1));
            }
        }

        public void Dispose()
        {
        }
    }
}
