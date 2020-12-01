using Cats.CertificateTransparency.Api;
using Cats.CertificateTransparency.Services;
using Refit;
using System;

namespace Cats.CertificateTransparency
{
    public static partial class Instance
    {
        private static readonly Lazy<ILogListService> DefaultLogListService =
           new Lazy<ILogListService>(() =>
           {
               var logListApi = RestService.For<ILogListApi>(Constants.GoogleLogListUrl);
               var logStoreService = new LogStoreService();
               return new LogListService(logListApi, logStoreService);
           });

        private static readonly Lazy<ICertificateTransparencyVerifier> DefaultCertVerifier =
           new Lazy<ICertificateTransparencyVerifier>(() =>
           {               
               var hostnameValidator = new HostnameAlwaysTrue();
               var ctPolicy = new CtPolicyDefault();
               return new CertificateTransparencyVerifier(hostnameValidator, LogListService, ctPolicy);
           });

        public static ILogListService LogListService => DefaultLogListService.Value;
        public static ICertificateTransparencyVerifier CertificateTransparencyVerifier => DefaultCertVerifier.Value;
    }
}
