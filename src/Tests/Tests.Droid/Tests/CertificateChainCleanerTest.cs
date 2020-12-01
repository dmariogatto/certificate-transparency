using Cats.CertificateTransparency;
using Tests.Droid;
using Java.Security.Cert;
using Javax.Net.Ssl;
using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;

namespace Tests
{
    [TestFixture]
    public class CertificateChainCleanerTest
    {
        private readonly IList<X509Certificate> _expectedChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                Data.PRE_CERT_SIGNING_BY_INTERMEDIATE,
                Data.INTERMEDIATE_CA_CERT,
                Data.ROOT_CA_CERT).ToJavaCerts();

        [Test]
        public void NoLeafCertificateInChainThrowsException()
        {
            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner();

            // when we clean an empty certificate chain
            // then an exception is thrown
            Assert.Throws<SSLPeerUnverifiedException>(() => chainCleaner.Clean(Enumerable.Empty<X509Certificate>()));
        }

        [Test]
        public void CleaningValidChainReturnsSuccessfully()
        {
            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner();

            // when we clean a valid chain
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                Data.PRE_CERT_SIGNING_BY_INTERMEDIATE,
                Data.INTERMEDIATE_CA_CERT).ToJavaCerts();

            var builtChain = chainCleaner.Clean(certsChain);
            
            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void CleaningIncompleteChainThrowsException()
        {
            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner();

            // when we clean a chain with missing certs (TestData.PRE_CERT_SIGNING_BY_INTERMEDIATE)
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                Data.INTERMEDIATE_CA_CERT).ToJavaCerts();
                        
            Assert.Throws<SSLPeerUnverifiedException>(() => chainCleaner.Clean(certsChain));
        }

        [Test]
        public void CleaningOutOfOrderChainReturnsSuccessfully()
        {
            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner();

            // when we clean a valid chain
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                Data.INTERMEDIATE_CA_CERT,
                Data.PRE_CERT_SIGNING_BY_INTERMEDIATE).ToJavaCerts();

            var builtChain = chainCleaner.Clean(certsChain);

            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void CleaningChainWithExtraCertsReturnsSuccessfully()
        {
            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner();

            // when we clean a valid chain
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,

                // unnecessary certs
                Data.TEST_PRE_CERT,
                Data.TEST_CERT,
                Data.TEST_INTERMEDIATE_CERT,
                Data.PRE_CERT_SIGNING_BY_INTERMEDIATE,

                Data.INTERMEDIATE_CA_CERT).ToJavaCerts();

            var builtChain = chainCleaner.Clean(certsChain);

            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void CleaningChainWithOnlyLeafThrowsException()
        {
            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner();

            // when we clean a valid chain
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE).ToJavaCerts();

            Assert.Throws<SSLPeerUnverifiedException>(() => chainCleaner.Clean(certsChain));
        }

        [Test]
        public void LargeValidChainReturnsSuccessfully()
        {
            var rootCert = Data.LoadCerts(
                Data.TEN_CERTS_ROOT_CERT).ToJavaCerts()[0];
            var certsChain = Data.LoadCerts(
                Data.TEN_CERTS_CHAIN).ToJavaCerts();

            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner(rootCert);

            // when we clean a chain of exactly 10 certs
            var builtChain = chainCleaner.Clean(certsChain);

            var expected = certsChain.ToList();
            expected.Add(rootCert);

            // then the expected chain is returned
            Assert.True(expected.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void TrustedCertInMiddleOfChainReturnsSuccessfully()
        {
            var certsChain = Data.LoadCerts(
                Data.TEN_CERTS_CHAIN).ToJavaCerts();
            var trustedCert = certsChain[5];

            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner(trustedCert);

            // when we clean a chain of exactly 10 certs
            var builtChain = chainCleaner.Clean(certsChain);

            // then the expected chain is returned
            Assert.True(certsChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void ReallyLargeValidChainThrowsException()
        {
            var rootCert = Data.LoadCerts(
                Data.ELEVEN_CERTS_ROOT_CERT).ToJavaCerts()[0];
            var certsChain = Data.LoadCerts(
                Data.ELEVEN_CERTS_CHAIN).ToJavaCerts();

            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner(rootCert);

            // when we clean a chain with more than 10 certs (inc root)
            Assert.Throws<SSLPeerUnverifiedException>(() => chainCleaner.Clean(certsChain));
        }

        [Test]
        public void TrustedSelfSignedRootCertReturnsSuccessfully()
        {
            var rootCert = Data.LoadCerts(
                Data.SELF_SIGNED_ROOT_CERT).ToJavaCerts()[0];

            // given a basic chain cleaner
            var chainCleaner = GetChainCleaner(rootCert);

            var certsChain = new[] { rootCert };

            // when we clean a chain of the self-signed root cert
            var builtChain = chainCleaner.Clean(certsChain);

            // then the expected chain is returned
            Assert.True(certsChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        private ICertificateChainCleaner GetChainCleaner(X509Certificate rootCert = null)
        {
            var trustManager = new Moq.Mock<IX509TrustManager>();
            trustManager.Setup(tm => tm.GetAcceptedIssuers())
                        .Returns(rootCert == null
                                 ? Data.LoadCerts(Data.ROOT_CA_CERT)
                                       .ToJavaCerts()
                                       .ToArray()
                                 : new[] { rootCert });

            return new CertificateChainCleaner(trustManager.Object);
        }
    }
}