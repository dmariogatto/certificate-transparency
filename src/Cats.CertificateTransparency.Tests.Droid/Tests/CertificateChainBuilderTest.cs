using Cats.CertificateTransparency.Android;
using Cats.CertificateTransparency.Tests.Droid;
using Java.Security.Cert;
using Javax.Net.Ssl;
using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;

namespace Cats.CertificateTransparency.Tests
{
    [TestFixture]
    public class CertificateChainBuilderTest
    {
        private readonly IList<X509Certificate> _expectedChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                TestData.Certificates.PRE_CERT_SIGNING_BY_INTERMEDIATE,
                TestData.Certificates.INTERMEDIATE_CA_CERT,
                TestData.Certificates.ROOT_CA_CERT).ToJavaCerts();

        [Test]
        public void NoLeafCertificateInChainThrowsException()
        {
            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder();

            // when we clean an empty certificate chain
            // then an exception is thrown
            Assert.Throws<SSLPeerUnverifiedException>(() => chainBuilder.GetCertificateChain(Enumerable.Empty<X509Certificate>()));
        }

        [Test]
        public void CleaningValidChainReturnsSuccessfully()
        {
            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder();

            // when we clean a valid chain
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                TestData.Certificates.PRE_CERT_SIGNING_BY_INTERMEDIATE,
                TestData.Certificates.INTERMEDIATE_CA_CERT).ToJavaCerts();

            var builtChain = chainBuilder.GetCertificateChain(certsChain);
            
            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void CleaningIncompleteChainThrowsException()
        {
            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder();

            // when we clean a chain with missing certs (TestData.PRE_CERT_SIGNING_BY_INTERMEDIATE)
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                TestData.Certificates.INTERMEDIATE_CA_CERT).ToJavaCerts();
                        
            Assert.Throws<SSLPeerUnverifiedException>(() => chainBuilder.GetCertificateChain(certsChain));
        }

        [Test]
        public void CleaningOutOfOrderChainReturnsSuccessfully()
        {
            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder();

            // when we clean a valid chain
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                TestData.Certificates.INTERMEDIATE_CA_CERT,
                TestData.Certificates.PRE_CERT_SIGNING_BY_INTERMEDIATE).ToJavaCerts();

            var builtChain = chainBuilder.GetCertificateChain(certsChain);

            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void CleaningChainWithExtraCertsReturnsSuccessfully()
        {
            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder();

            // when we clean a valid chain
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,

                // unnecessary certs
                TestData.Certificates.TEST_PRE_CERT,
                TestData.Certificates.TEST_CERT,
                TestData.Certificates.TEST_INTERMEDIATE_CERT,
                TestData.Certificates.PRE_CERT_SIGNING_BY_INTERMEDIATE,

                TestData.Certificates.INTERMEDIATE_CA_CERT).ToJavaCerts();

            var builtChain = chainBuilder.GetCertificateChain(certsChain);

            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void CleaningChainWithOnlyLeafThrowsException()
        {
            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder();

            // when we clean a valid chain
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE).ToJavaCerts();

            Assert.Throws<SSLPeerUnverifiedException>(() => chainBuilder.GetCertificateChain(certsChain));
        }

        [Test]
        public void LargeValidChainReturnsSuccessfully()
        {
            var rootCert = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEN_CERTS_ROOT_CERT).ToJavaCerts()[0];
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEN_CERTS_CHAIN).ToJavaCerts();

            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder(rootCert);

            // when we clean a chain of exactly 10 certs
            var builtChain = chainBuilder.GetCertificateChain(certsChain);

            var expected = certsChain.ToList();
            expected.Add(rootCert);

            // then the expected chain is returned
            Assert.True(expected.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void TrustedCertInMiddleOfChainReturnsSuccessfully()
        {
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEN_CERTS_CHAIN).ToJavaCerts();
            var trustedCert = certsChain[5];

            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder(trustedCert);

            // when we clean a chain of exactly 10 certs
            var builtChain = chainBuilder.GetCertificateChain(certsChain);

            // then the expected chain is returned
            Assert.True(certsChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        [Test]
        public void ReallyLargeValidChainThrowsException()
        {
            var rootCert = TestData.Certificates.LoadCerts(
                TestData.Certificates.ELEVEN_CERTS_ROOT_CERT).ToJavaCerts()[0];
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.ELEVEN_CERTS_CHAIN).ToJavaCerts();

            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder(rootCert);

            // when we clean a chain with more than 10 certs (inc root)
            Assert.Throws<SSLPeerUnverifiedException>(() => chainBuilder.GetCertificateChain(certsChain));
        }

        [Test]
        public void TrustedSelfSignedRootCertReturnsSuccessfully()
        {
            var rootCert = TestData.Certificates.LoadCerts(
                TestData.Certificates.SELF_SIGNED_ROOT_CERT).ToJavaCerts()[0];

            // given a basic chain cleaner
            var chainBuilder = GetCertificateChainBuilder(rootCert);

            var certsChain = new[] { rootCert };

            // when we clean a chain of the self-signed root cert
            var builtChain = chainBuilder.GetCertificateChain(certsChain);

            // then the expected chain is returned
            Assert.True(certsChain.SequenceEqual(builtChain, new JavaX509CertificateEquality()));
        }

        private ICertificateChainBuilder GetCertificateChainBuilder(X509Certificate rootCert = null)
        {
            var trustManager = new Moq.Mock<IX509TrustManager>();
            trustManager.Setup(tm => tm.GetAcceptedIssuers())
                        .Returns(rootCert == null
                                 ? TestData.Certificates
                                           .LoadCerts(TestData.Certificates.ROOT_CA_CERT)
                                           .ToJavaCerts()
                                           .ToArray()
                                 : new[] { rootCert });

            return new Android.CertificateChainBuilder(trustManager.Object);
        }
    }
}