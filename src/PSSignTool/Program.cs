using System;
using Microsoft.Extensions.CommandLineUtils;

namespace PSSignTool
{
    class Program
    {
        static int Main(string[] args)
        {
            var application = new CommandLineApplication(false);
            var signCommand = application.Command("sign", throwOnUnexpectedArg: false, configuration: signConfiguration =>
            {
                signConfiguration.Description = "Signs a PowerShell script or module.";
                signConfiguration.HelpOption("-? | -h | --help");
                var timestamp = signConfiguration.Option("-t | --timestamp", "A URL of the timestamping server to timestamp the signature.", CommandOptionType.SingleValue);
                var timestampAlgorithm = signConfiguration.Option("-ta | --timestamp-algorithm", "The digest algorithm of the timestamp.", CommandOptionType.SingleValue);
                var fileDigest = signConfiguration.Option("-fd | --file-digest", "A URL of the timestamping server to timestamp the signature.", CommandOptionType.SingleValue);
                var force = signConfiguration.Option("-f | --force", "Force the signature by overwriting any existing signatures.", CommandOptionType.NoValue);
                var file = signConfiguration.Argument("file", "The ps1 or psm1 file.");

                var azureKeyVaultUrl = signConfiguration.Option("-kvu | --azure-key-vault-url", "The URL to an Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultClientId = signConfiguration.Option("-kvi | --azure-key-vault-client-id", "The Client ID to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultClientSecret = signConfiguration.Option("-kvs | --azure-key-vault-client-secret", "The Client Secret to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultCertificateName = signConfiguration.Option("-kvc | --azure-key-vault-certificate", "The name of the certificate in Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultAccessToken = signConfiguration.Option("-kva | --azure-key-vault-accesstoken", "The Access Token to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);


                signConfiguration.OnExecute(() =>
                {
                    var sign = new SignCommand(signConfiguration);
                    
                    return sign.SignAzure(azureKeyVaultUrl, azureKeyVaultClientId, azureKeyVaultClientSecret,
                                                azureKeyVaultCertificateName, azureKeyVaultAccessToken, force, fileDigest, timestamp, timestampAlgorithm, file);
                    
                });
            });

            application.HelpOption("-? | -h | --help");
            application.VersionOption("-v | --version", typeof(Program).Assembly.GetName().Version.ToString(3));
            if (args.Length == 0)
            {
                application.ShowHelp();
            }
            return application.Execute(args);
        }
    }
}
