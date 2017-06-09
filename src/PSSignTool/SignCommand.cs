using Microsoft.Extensions.CommandLineUtils;
using PSSignTool.Core;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OpenVsixSignTool.Core;

namespace PSSignTool
{
    class SignCommand
    {
        internal static class EXIT_CODES
        {
            public const int SUCCESS = 0;
            public const int INVALID_OPTIONS = 1;
            public const int FAILED = 2;
        }

        readonly CommandLineApplication _signCommandApplication;

        public SignCommand(CommandLineApplication signCommandApplication)
        {
            _signCommandApplication = signCommandApplication;
        }

        internal async Task<int> SignAzure(CommandOption azureKeyVaultUrl, CommandOption azureKeyVaultClientId,
                                           CommandOption azureKeyVaultClientSecret, CommandOption azureKeyVaultCertificateName, CommandOption azureKeyVaultAccessToken, CommandOption force,
                                           CommandOption fileDigest, CommandOption timestampUrl, CommandOption timestampAlgorithm, CommandArgument ps1Path)
        {
            if (!azureKeyVaultUrl.HasValue())
            {
                _signCommandApplication.Out.WriteLine("The Azure Key Vault URL must be specified for Azure signing.");
                return EXIT_CODES.INVALID_OPTIONS;
            }


            // we only need the client id/secret if we don't have an access token
            if (!azureKeyVaultAccessToken.HasValue())
            {
                if (!azureKeyVaultClientId.HasValue())
                {
                    _signCommandApplication.Out.WriteLine("The Azure Key Vault Client ID or Access Token must be specified for Azure signing.");
                    return EXIT_CODES.INVALID_OPTIONS;
                }

                if (!azureKeyVaultClientSecret.HasValue())
                {
                    _signCommandApplication.Out.WriteLine("The Azure Key Vault Client Secret or Access Token must be specified for Azure signing.");
                    return EXIT_CODES.INVALID_OPTIONS;
                }
            }

            if (!azureKeyVaultCertificateName.HasValue())
            {
                _signCommandApplication.Out.WriteLine("The Azure Key Vault Client Certificate Name must be specified for Azure signing.");
                return EXIT_CODES.INVALID_OPTIONS;
            }
            Uri timestampServer = null;
            if (timestampUrl.HasValue())
            {
                if (!Uri.TryCreate(timestampUrl.Value(), UriKind.Absolute, out timestampServer))
                {
                    _signCommandApplication.Out.WriteLine("Specified timestamp URL is invalid.");
                    return EXIT_CODES.FAILED;
                }
                if (timestampServer.Scheme != Uri.UriSchemeHttp && timestampServer.Scheme != Uri.UriSchemeHttps)
                {
                    _signCommandApplication.Out.WriteLine("Specified timestamp URL is invalid.");
                    return EXIT_CODES.FAILED;
                }
            }
            var vsixPathValue = ps1Path.Value;
            if (!File.Exists(vsixPathValue))
            {
                _signCommandApplication.Out.WriteLine("Specified file does not exist.");
                return EXIT_CODES.FAILED;
            }
            HashAlgorithmName fileDigestAlgorithm, timestampDigestAlgorithm;
            var fileDigestResult = AlgorithmFromInput(fileDigest.HasValue() ? fileDigest.Value() : null);
            if (fileDigestResult == null)
            {
                _signCommandApplication.Out.WriteLine("Specified file digest algorithm is not supported.");
                return EXIT_CODES.INVALID_OPTIONS;
            }
            else
            {
                fileDigestAlgorithm = fileDigestResult.Value;
            }
            var timestampDigestResult = AlgorithmFromInput(timestampAlgorithm.HasValue() ? timestampAlgorithm.Value() : null);
            if (timestampDigestResult == null)
            {
                _signCommandApplication.Out.WriteLine("Specified timestamp digest algorithm is not supported.");
                return EXIT_CODES.INVALID_OPTIONS;
            }
            else
            {
                timestampDigestAlgorithm = timestampDigestResult.Value;
            }
            return await PerformAzureSignOnVsixAsync(
                       vsixPathValue,
                       force.HasValue(),
                       timestampServer,
                       fileDigestAlgorithm,
                       timestampDigestAlgorithm,
                       azureKeyVaultUrl.Value(),
                       azureKeyVaultClientId.Value(),
                       azureKeyVaultCertificateName.Value(),
                       azureKeyVaultClientSecret.Value(),
                       azureKeyVaultAccessToken.Value()
                   );
        }

        private async Task<int> PerformAzureSignOnVsixAsync(string vsixPath, bool force,
                                                            Uri timestampUri, HashAlgorithmName fileDigestAlgorithm, HashAlgorithmName timestampDigestAlgorithm,
                                                            string azureUri, string azureClientId, string azureClientCertificateName, string azureClientSecret, string azureAccessToken
        )
        {
            using (var package = OpcPackage.Open(vsixPath, OpcPackageFileMode.ReadWrite))
            {
                if (package.GetSignatures().Any() && !force)
                {
                    _signCommandApplication.Out.WriteLine("The VSIX is already signed.");
                    return EXIT_CODES.FAILED;
                }
                var signBuilder = package.CreateSignatureBuilder();
                signBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                var signingConfiguration = new AzureKeyVaultSignConfigurationSet
                {
                    FileDigestAlgorithm = fileDigestAlgorithm,
                    PkcsDigestAlgorithm = fileDigestAlgorithm,
                    AzureClientId = azureClientId,
                    AzureClientSecret = azureClientSecret,
                    AzureKeyVaultCertificateName = azureClientCertificateName,
                    AzureKeyVaultUrl = azureUri,
                    AzureAccessToken = azureAccessToken
                };

                var signature = await signBuilder.SignAsync(signingConfiguration);
                if (timestampUri != null)
                {
                    var timestampBuilder = signature.CreateTimestampBuilder();
                    var result = await timestampBuilder.SignAsync(timestampUri, timestampDigestAlgorithm);
                    if (result == TimestampResult.Failed)
                    {
                        return EXIT_CODES.FAILED;
                    }
                }
                _signCommandApplication.Out.WriteLine("The signing operation is complete.");
                return EXIT_CODES.SUCCESS;
            }
        }

        private static HashAlgorithmName? AlgorithmFromInput(string value)
        {
            switch (value?.ToLower())
            {
                case "sha1":
                    return HashAlgorithmName.SHA1;
                case "sha384":
                    return HashAlgorithmName.SHA384;
                case "sha512":
                    return HashAlgorithmName.SHA512;
                case null:
                case "sha256":
                    return HashAlgorithmName.SHA256;
                default:
                    return null;

            }
        }
    }
}