using Cats.CertificateTransparency.Api;
using Cats.CertificateTransparency.Services;
using Refit;
using System;

namespace Cats.CertificateTransparency
{
    public static class Instance
    {
        private static readonly Lazy<ICertificateTransparencyVerifier> DefaultCertVerifier =
           new Lazy<ICertificateTransparencyVerifier>(() =>
           {
               var logListApi = RestService.For<ILogListApi>(Constants.GoogleLogListUrl);
               var logStoreService = new LogStoreService();
               var logListService = new LogListService(logListApi, logStoreService);
               var hostnameValidator = new HostnameAlwaysTrue();
               var ctPolicy = new CtPolicyDefault();
               return new CertificateTransparencyVerifier(hostnameValidator, logListService, ctPolicy);
           });

        public static ICertificateTransparencyVerifier CertificateTransparencyVerifier => DefaultCertVerifier.Value;        
    }
}
