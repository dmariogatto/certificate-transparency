using Cats.CertificateTransparency;
using Cats.CertificateTransparency.Models;
using Cats.CertificateTransparency.Services;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Tests
{
    public class CertificateTransparencyVerifierTest
    {
        private const string BabylonHealthCom = "www.babylonhealth.com";
        private const string AllowedRandomCom = "allowed.random.com";
        private const string DisallowedRandomCom = "disallowed.random.com";

        private readonly string[] _includeBabylon = new [] { "*.babylonhealth.com" };
        private readonly string[] _includeRandom = new [] { "*.random.com" };

        [Test]
        public void MitmDisallowedWhenHostChecked()
        {
            var ctv = GetCertVerifier(_includeBabylon);

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ATTACK_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(BabylonHealthCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.NoScts);
        }

        [Test]
        public void MitmAttackAllowedWhenHostNotChecked()
        {
            var ctv = GetCertVerifier(_includeRandom);

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ATTACK_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(BabylonHealthCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.DisabledForHost);
        }

        [Test]
        public void OriginalChainAllowedWhenHostNotChecked()
        {
            var ctv = GetCertVerifier(_includeRandom);

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(BabylonHealthCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.DisabledForHost);
        }

        [Test]
        public void OriginalChainAllowedWhenHostChecked()
        {
            var ctv = GetCertVerifier(_includeBabylon);

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(BabylonHealthCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.Trusted);
            Assert.AreEqual(2, result.SctResults.Count(kv => kv.Value.IsValid));
        }

        [Test]
        public void UntrustedCertificateThrowsException()
        {
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ATTACK_CHAIN);

            try
            {
                var certsChain = CertificateChainBuilder.Build(certsToCheck);
                Assert.AreEqual(certsChain, null);
            }
            catch
            {
                Assert.IsTrue(true);
            }
        }

        [Test]
        public void NoHostsDefinedDoesNotThrowException()
        {
            var ctv = GetCertVerifier();
            Assert.IsTrue(ctv is ICertificateTransparencyVerifier);
        }

        [Test]
        public void OriginalChainDisallowedWhenEmptyLogs()
        {
            var ctv = GetCertVerifierNoLogs(_includeBabylon);

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(BabylonHealthCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.LogServersFailed);
        }

        [Test]
        public void OriginalChainDisallowedWhenNullLogs()
        {
            var ctv = GetCertVerifierNoLogs(_includeBabylon);

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(BabylonHealthCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.LogServersFailed);
        }

        [Test]
        public void OriginalChainDisallowedWhenOnlyOneSct()
        {
            var ctv = GetCertVerifier(_includeBabylon);

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var certWithSingleSct = SingleSctOnly(certsChain.First());
            certsChain.RemoveAt(0);
            certsChain.Insert(0, certWithSingleSct);

            var result = ctv.IsValidAsync(BabylonHealthCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.TooFewSctsTrusted);
        }

        [Test]
        public void NoCertificatesDisallowed()
        {
            var ctv = GetCertVerifier(_includeBabylon);
                        
            var result = ctv.IsValidAsync(BabylonHealthCom, new List<X509Certificate2>(0), default).Result;

            Assert.IsTrue(result.Result == CtResult.NoCertificates);
        }

        [Test]
        public void IncludeHostsRuleMatchesSubdomain()
        {
            var ctv = GetCertVerifier(_includeRandom);

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(AllowedRandomCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.Trusted);
        }

        [Test]
        public void ExcludeHostsRuleBlocksSubdomainMatching()
        {
            var ctv = GetCertVerifier(_includeRandom, new [] { DisallowedRandomCom });

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(DisallowedRandomCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.DisabledForHost);
        }

        [Test]
        public void IncludeAllHostsRuleMatchesDomain()
        {
            var ctv = GetCertVerifier(new[] { "*.*" });

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(AllowedRandomCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.Trusted);
        }

        [Test]
        public void ExcludeHostFromAllRuleBlocksMatching()
        {
            var ctv = GetCertVerifier(new[] { "*.*" }, new[] { AllowedRandomCom });

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(AllowedRandomCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.DisabledForHost);
        }

        [Test]
        public void ExcludeHostsRuleOnlyBlocksSpecifiedSubdomainMatching()
        {
            var ctv = GetCertVerifier(new[] { "*.*" }, new[] { DisallowedRandomCom });

            var rootCert = Data.LoadCerts(Data.TEST_MITMPROXY_ROOT_CERT);
            var certsToCheck = Data.LoadCerts(Data.TEST_MITMPROXY_ORIGINAL_CHAIN);

            var certsChain = CertificateChainBuilder.Build(certsToCheck, rootCert.Single());

            var result = ctv.IsValidAsync(AllowedRandomCom, certsChain, default).Result;

            Assert.IsTrue(result.Result == CtResult.Trusted);
        }

        [Test]
        public void EmptyCleanedCertificateChainFailsWithNoCertificates()
        {
            var ctv = GetCertVerifier(new[] { "*.*" });

            var result = ctv.IsValidAsync(AllowedRandomCom, new List<X509Certificate2>(0), default).Result;

            Assert.IsTrue(result.Result == CtResult.NoCertificates);
        }

        [Test]
        public void ExcludeHostsWithWildcardNotAllowed()
        {            
            Assert.Throws<ArgumentException>(() => GetCertVerifier(new[] { AllowedRandomCom }, _includeRandom));
        }

        [Test]
        public void ExcludeHostMatchingIncludeNotAllowed()
        {
            Assert.Throws<ArgumentException>(() => GetCertVerifier(new[] { AllowedRandomCom }, new[] { AllowedRandomCom }));
        }

        private ICertificateTransparencyVerifier GetCertVerifier(IEnumerable<string> inclHostPatterns = null, IEnumerable<string> exclHostPatterns = null)
        {
            var logListRoot = Data.LoadJson<LogListRoot>(Data.TEST_LOG_LIST_JSON);
            var logDictionary = logListRoot.ToDictionary();

            var logService = new Moq.Mock<ILogListService>();

            logService
                .Setup(m => m.GetLogListRootAsync(default))
                .Returns(() => Task.FromResult(logListRoot));
            logService
                .Setup(m => m.GetLogDictionaryAsync(default))
                .Returns(() => Task.FromResult(logDictionary));

            var hostnameValidator = inclHostPatterns?.Any() == true
                ? new HostnamePattern(inclHostPatterns, exclHostPatterns)
                : new HostnameAlwaysTrue() as IHostnameValidator;
            var ctPolicy = new CtPolicyDefault();

            return new CertificateTransparencyVerifier(hostnameValidator, logService.Object, ctPolicy);
        }

        private ICertificateTransparencyVerifier GetCertVerifierNoLogs(IEnumerable<string> inclHostPatterns = null, IEnumerable<string> exclHostPatterns = null)
        {
            var logService = new Moq.Mock<ILogListService>();

            logService
                .Setup(m => m.GetLogListRootAsync(default))
                .Returns(() => Task.FromResult(default(LogListRoot)));
            logService
                .Setup(m => m.GetLogDictionaryAsync(default))
                .Returns(() => Task.FromResult<IDictionary<string, Log>>(new Dictionary<string, Log>(0)));

            var hostnameValidator = inclHostPatterns?.Any() == true
                ? new HostnamePattern(inclHostPatterns, exclHostPatterns)
                : new HostnameAlwaysTrue() as IHostnameValidator;
            var ctPolicy = new CtPolicyDefault();

            return new CertificateTransparencyVerifier(hostnameValidator, logService.Object, ctPolicy);
        }

        private X509Certificate2 SingleSctOnly(X509Certificate2 certificate)
        {
            var moqCert = new Moq.Mock<MoqX509Certificate2>(certificate) { CallBase = true };
            moqCert.Setup(c => c.MoqNotBefore).Returns(certificate.NotBefore);
            moqCert.Setup(c => c.MoqNotAfter).Returns(certificate.NotAfter);
            moqCert
                .Setup(c => c.GetMoqExtensions())
                .Returns(() =>
                {
                    var newCollection = new X509ExtensionCollection();

                    foreach (var ext in certificate.Extensions)
                    {
                        if (ext.Oid.Value.Equals(Constants.SctCertificateOid))
                        {
                            var bytes = Convert.FromBase64String("BHwEegB4AHYAu9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFj7ztQ3wAABAMARzBFAiEA53gntK6Dnr6ROwYGBjqjt5dS4tWM6Zw/TtxIxOvobW8CIF3n4XjIX7/w66gThQD47iF7YmxelwgUQgPzEWNlHQiu");
                            var newSct = new X509Extension(Constants.SctCertificateOid, bytes, ext.Critical);
                            newCollection.Add(newSct);
                        }
                        else
                        {
                            newCollection.Add(ext);
                        }
                    }

                    return newCollection;
                });

            return moqCert.Object;
        }        
    }    
}