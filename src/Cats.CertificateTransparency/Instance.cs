using Cats.CertificateTransparency.Api;
using Cats.CertificateTransparency.Services;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Cats.CertificateTransparency
{
    public static partial class Instance
    {
        private static readonly Lazy<ILogListService> DefaultLogListService =
           new Lazy<ILogListService>(() =>
           {
               var logListApi = new GoogleLogListApi(Constants.GoogleLogListUrl);
               var logStoreService = new LogStoreService();
               return new LogListZipService(logListApi, logStoreService);
           });

        private static readonly Lazy<ICertificateTransparencyVerifier> DefaultCertVerifier =
           new Lazy<ICertificateTransparencyVerifier>(() =>
           {
               var hostnameValidator = IncludedDomains?.Any() == true
                                       ? new HostnamePattern(IncludedDomains, ExcludedDomains)
                                       : new HostnameAlwaysTrue() as IHostnameValidator;
               var ctPolicy = new CtPolicyDefault();
               return new CertificateTransparencyVerifier(hostnameValidator, LogListService, ctPolicy);
           });


        private static IReadOnlyCollection<string> IncludedDomains = null;
        private static IReadOnlyCollection<string> ExcludedDomains = null;

        public static void InitDomains(IEnumerable<string> includedDomains, IEnumerable<string> excludedDomains)
        {
            if (IncludedDomains != null || ExcludedDomains != null)
                throw new InvalidOperationException($"{nameof(InitDomains)}() can only be called once!");

            if (DefaultCertVerifier.IsValueCreated)
                throw new InvalidOperationException($"{nameof(InitDomains)}() can only be called before any calls to {nameof(CertificateTransparencyVerifier)}!");

            if (includedDomains?.Any() != true)
                throw new InvalidOperationException($"Parameter '{nameof(includedDomains)}' must have at least one entry!");

            IncludedDomains = includedDomains?.ToList() ?? new List<string>(0);
            ExcludedDomains = excludedDomains?.ToList() ?? new List<string>(0);
        }

        public static ILogListService LogListService => DefaultLogListService.Value;
        public static ICertificateTransparencyVerifier CertificateTransparencyVerifier => DefaultCertVerifier.Value;
    }
}
