using Cats.CertificateTransparency;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Samples.Console
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Instance.InitDomains(new[] { "*.*" }, null);
            var certVerifier = Instance.CertificateTransparencyVerifier;

            var path = args.Length > 0
                ? args[0]
                : @$"{AppDomain.CurrentDomain.BaseDirectory}\certificates";
            var di = new DirectoryInfo(path);
            var files = di.Exists
                        ? di.GetFiles().Where(i => i.Extension.Equals(".cer", StringComparison.OrdinalIgnoreCase)).ToList()
                        : new List<FileInfo>(0);

            System.Console.WriteLine($"Found {files.Count} certs to validate!");

            foreach (var f in files)
            {
                System.Console.WriteLine($"Validating '{f.Name}'");

                var certificate = new X509Certificate2(f.FullName);

                var certChain = new X509Chain();
                certChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                certChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;

                var isValidChain = certChain.Build(certificate);
                var certs = certChain.ChainElements.OfType<X509ChainElement>().Select(i => i.Certificate).ToList();
                if (isValidChain)
                {
                    var ctResult = await certVerifier.IsValidAsync(certs, default);
                    if (ctResult.IsValid)
                    {
                        System.Console.WriteLine($"Valid! Result: {ctResult.Description}");
                    }
                    else
                    {
                        System.Console.WriteLine($"NOT Valid! Result: {ctResult.Description}");
                    }
                }
            }

            System.Console.WriteLine();

            var urlsToValidate = new List<string>();

            urlsToValidate.AddRange(args.Where(i => Uri.TryCreate(i, UriKind.Absolute, out _)));

            if (!urlsToValidate.Any())
            {
                urlsToValidate.Add("https://www.google.com.au");
                urlsToValidate.Add("https://github.com/");
                urlsToValidate.Add("https://www.microsoft.com/");
            }

            System.Console.WriteLine($"Found {urlsToValidate.Count} URLs to validate!");

            var client = new HttpClient(new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = (request, certificate, certChain, sslPolicyErrors) =>
                {
                    System.Console.WriteLine($"Validating request '{request.RequestUri}'");
                    var certs = certChain.ChainElements.OfType<X509ChainElement>().Select(i => i.Certificate).ToArray();
                    var ctValueTask = certVerifier.IsValidAsync(request.RequestUri.Host, certs, default);
                    var ctResult = ctValueTask.IsCompleted
                        ? ctValueTask.Result
                        : ctValueTask.AsTask().Result;

                    if (ctResult.IsValid)
                    {
                        System.Console.WriteLine($"Valid! Result: {ctResult.Description}");
                    }
                    else
                    {
                        System.Console.WriteLine($"NOT Valid! Result: {ctResult.Description}");
                    }

                    return true;
                }
            });

            foreach (var url in urlsToValidate)
            {
                await client.GetAsync(url);
            }
        }
    }
}
