using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Tests
{
    [TestFixture]    
    public class CertificateChainBuilderTest
    {
        private readonly IList<X509Certificate2> _expectedChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                TestData.Certificates.PRE_CERT_SIGNING_BY_INTERMEDIATE,
                TestData.Certificates.INTERMEDIATE_CA_CERT,
                TestData.Certificates.ROOT_CA_CERT);

        [Test]
        public void CleaningValidChainReturnsSuccessfully()
        {
            // when we clean a valid chain
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                TestData.Certificates.PRE_CERT_SIGNING_BY_INTERMEDIATE,
                TestData.Certificates.INTERMEDIATE_CA_CERT);

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1));

            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain));
        }

        [Test]
        public void CleaningIncompleteChainThrowsException()
        {
            // when we clean a chain with missing certs (TestData.PRE_CERT_SIGNING_BY_INTERMEDIATE)
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                TestData.Certificates.INTERMEDIATE_CA_CERT);

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1));

            Assert.AreEqual(builtChain, null);
        }

        [Test]
        public void CleaningOutOfOrderChainReturnsSuccessfully()
        {
            // when we clean a valid chain
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,
                TestData.Certificates.INTERMEDIATE_CA_CERT,
                TestData.Certificates.PRE_CERT_SIGNING_BY_INTERMEDIATE);

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1));

            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain));
        }

        [Test]
        public void CleaningChainWithExtraCertsReturnsSuccessfully()
        {
            // when we clean a valid chain
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE,

                // unnecessary certs
                TestData.Certificates.TEST_PRE_CERT,
                TestData.Certificates.TEST_CERT,
                TestData.Certificates.TEST_INTERMEDIATE_CERT,
                TestData.Certificates.PRE_CERT_SIGNING_BY_INTERMEDIATE,

                TestData.Certificates.INTERMEDIATE_CA_CERT);

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1));

            // then the expected chain is returned
            Assert.True(_expectedChain.SequenceEqual(builtChain));
        }

        [Test]
        public void CleaningChainWithOnlyLeafThrowsException()
        {
            // when we clean a valid chain
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE);

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1));

            Assert.AreEqual(builtChain, null);
        }

        [Test]
        public void LargeValidChainReturnsSuccessfully()
        {
            var rootCert = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEN_CERTS_ROOT_CERT)[0];
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEN_CERTS_CHAIN);

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1), rootCert);

            var expected = certsChain.ToList();
            expected.Add(rootCert);

            // then the expected chain is returned
            Assert.True(expected.SequenceEqual(builtChain));
        }

        [Test]
        public void TrustedCertInMiddleOfChainReturnsSuccessfully()
        {
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.TEN_CERTS_CHAIN);
            var trustedCert = certsChain[5];

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1), trustedCert);

            // then the expected chain is returned
            Assert.True(certsChain.SequenceEqual(builtChain));
        }

        [Test]
        public void ReallyLargeValidChainThrowsException()
        {
            var rootCert = TestData.Certificates.LoadCerts(
                TestData.Certificates.ELEVEN_CERTS_ROOT_CERT)[0];
            var certsChain = TestData.Certificates.LoadCerts(
                TestData.Certificates.ELEVEN_CERTS_CHAIN);

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1), rootCert);

            // when we clean a chain with more than 10 certs (inc root)
            Assert.IsTrue(builtChain.Count > 10);
        }

        [Test]
        public void TrustedSelfSignedRootCertReturnsSuccessfully()
        {
            var rootCert = TestData.Certificates.LoadCerts(
                TestData.Certificates.SELF_SIGNED_ROOT_CERT)[0];

            var certsChain = new[] { rootCert };

            var builtChain = CertificateChainBuilder.Build(certsChain.First(), certsChain.Skip(1), rootCert);

            // then the expected chain is returned
            Assert.True(certsChain.SequenceEqual(builtChain));
        }
    }
}