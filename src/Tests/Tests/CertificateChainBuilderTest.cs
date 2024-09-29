using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Tests
{
    // https://github.com/babylonhealth/certificate-transparency-android/blob/main/certificatetransparency/src/test/kotlin/com/babylon/certificatetransparency/chaincleaner/BasicCertificateChainCleanerTest.kt

    [TestFixture]
    public class CertificateChainBuilderTest
    {
        private readonly IList<X509Certificate2> _expectedChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                Data.PRE_CERT_SIGNING_BY_INTERMEDIATE,
                Data.INTERMEDIATE_CA_CERT,
                Data.ROOT_CA_CERT);

        [Test]
        public void CleaningValidChainReturnsSuccessfully()
        {
            // when we clean a valid chain
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                Data.PRE_CERT_SIGNING_BY_INTERMEDIATE,
                Data.INTERMEDIATE_CA_CERT);

            var builtChain = CertificateChainBuilder.Build(certsChain);

            // then the expected chain is returned
            Assert.That(_expectedChain.SequenceEqual(builtChain));
        }

        [Test]
        public void CleaningIncompleteChainThrowsException()
        {
            // when we clean a chain with missing certs (TestData.PRE_CERT_SIGNING_BY_INTERMEDIATE)
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                Data.INTERMEDIATE_CA_CERT);

            var builtChain = CertificateChainBuilder.Build(certsChain);

            Assert.That(builtChain is null);
        }

        [Test]
        public void CleaningOutOfOrderChainReturnsSuccessfully()
        {
            // when we clean a valid chain
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                Data.INTERMEDIATE_CA_CERT,
                Data.PRE_CERT_SIGNING_BY_INTERMEDIATE);

            var builtChain = CertificateChainBuilder.Build(certsChain);

            // then the expected chain is returned
            Assert.That(_expectedChain.SequenceEqual(builtChain));
        }

        [Test]
        public void CleaningChainWithExtraCertsReturnsSuccessfully()
        {
            // when we clean a valid chain
            var certsChain = Data.LoadCerts(
                Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,

                // unnecessary certs
                Data.TEST_PRE_CERT,
                Data.TEST_CERT,
                Data.TEST_INTERMEDIATE_CERT,
                Data.PRE_CERT_SIGNING_BY_INTERMEDIATE,

                Data.INTERMEDIATE_CA_CERT);

            var builtChain = CertificateChainBuilder.Build(certsChain);

            // then the expected chain is returned
            Assert.That(_expectedChain.SequenceEqual(builtChain));
        }

        [Test]
        public void CleaningChainWithOnlyLeafThrowsException()
        {
            // when we clean a valid chain
            var certsChain = Data.LoadCerts(Data.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE);

            var builtChain = CertificateChainBuilder.Build(certsChain);

            Assert.That(builtChain is null);
        }

        [Test]
        public void LargeValidChainReturnsSuccessfully()
        {
            var rootCert = Data.LoadCerts(Data.TEN_CERTS_ROOT_CERT)[0];
            var certsChain = Data.LoadCerts(Data.TEN_CERTS_CHAIN);

            var builtChain = CertificateChainBuilder.Build(certsChain, rootCert);

            var expected = certsChain.ToList();
            expected.Add(rootCert);

            // then the expected chain is returned
            Assert.That(expected.SequenceEqual(builtChain));
        }

        [Test]
        public void TrustedCertInMiddleOfChainReturnsSuccessfully()
        {
            var certsChain = Data.LoadCerts(
                Data.TEN_CERTS_CHAIN);
            var trustedCert = certsChain[5];

            var builtChain = CertificateChainBuilder.Build(certsChain, trustedCert);

            // then the expected chain is returned
            Assert.That(certsChain.SequenceEqual(builtChain));
        }

        [Test]
        public void ReallyLargeValidChainThrowsException()
        {
            var rootCert = Data.LoadCerts(Data.ELEVEN_CERTS_ROOT_CERT)[0];
            var certsChain = Data.LoadCerts(Data.ELEVEN_CERTS_CHAIN);

            var builtChain = CertificateChainBuilder.Build(certsChain, rootCert);

            // when we clean a chain with more than 10 certs (inc root)
            Assert.That(builtChain.Count > 10);
        }

        [Test]
        public void TrustedSelfSignedRootCertReturnsSuccessfully()
        {
            var rootCert = Data.LoadCerts(Data.SELF_SIGNED_ROOT_CERT)[0];

            var certsChain = new[] { rootCert };

            var builtChain = CertificateChainBuilder.Build(certsChain, rootCert);

            // then the expected chain is returned
            Assert.That(certsChain.SequenceEqual(builtChain));
        }
    }
}