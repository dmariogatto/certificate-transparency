using Cats.CertificateTransparency.Models;
using Cats.CertificateTransparency.Services;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace Tests
{
    // https://github.com/babylonhealth/certificate-transparency-android/blob/main/certificatetransparency/src/test/kotlin/com/babylon/certificatetransparency/internal/verifier/DefaultPolicyTest.kt

    [TestFixture]
    public class CtPolicyDefaultTest
    {
        private readonly PolicyTestParams[] _testParams = new[]
        {
            new PolicyTestParams("Cert valid for -14 months (nonsensical), needs 2 SCTs", new DateTime(2016, 6, 6, 11, 25, 0, DateTimeKind.Utc), new DateTime(2015, 3, 25, 11, 25, 0, DateTimeKind.Utc), 2),
            new PolicyTestParams("Cert valid for 14 months, needs 2 SCTs", new DateTime(2015, 3, 25, 11, 25, 0, DateTimeKind.Utc), new DateTime(2016, 6, 6, 11, 25, 0, DateTimeKind.Utc), 2),
            new PolicyTestParams("Cert valid for exactly 15 months, needs 3 SCTs", new DateTime(2015, 3, 25, 11, 25, 0, DateTimeKind.Utc), new DateTime(2016, 6, 25, 11, 25, 0, DateTimeKind.Utc), 3),
            new PolicyTestParams("Cert valid for over 15 months, needs 3 SCTs", new DateTime(2015, 3, 25, 11, 25, 0, DateTimeKind.Utc), new DateTime(2016, 6, 27, 11, 25, 0, DateTimeKind.Utc), 3),
            new PolicyTestParams("Cert valid for exactly 27 months, needs 3 SCTs", new DateTime(2015, 3, 25, 11, 25, 0, DateTimeKind.Utc), new DateTime(2017, 6, 25, 11, 25, 0, DateTimeKind.Utc), 3),
            new PolicyTestParams("Cert valid for over 27 months, needs 4 SCTs", new DateTime(2015, 3, 25, 11, 25, 0, DateTimeKind.Utc), new DateTime(2017, 6, 28, 11, 25, 0, DateTimeKind.Utc), 4),
            new PolicyTestParams("Cert valid for exactly 39 months, needs 4 SCTs", new DateTime(2015, 3, 25, 11, 25, 0, DateTimeKind.Utc), new DateTime(2018, 6, 25, 11, 25, 0, DateTimeKind.Utc), 4),
            new PolicyTestParams("Cert valid for over 39 months, needs 5 SCTs", new DateTime(2015, 3, 25, 11, 25, 0, DateTimeKind.Utc), new DateTime(2018, 6, 27, 11, 25, 0, DateTimeKind.Utc), 5)
        };

        [Test]
        public void FewerSctsThanRequiredReturnsFailure()
        {
            var rand = new Random();

            foreach (var tp in _testParams)
            {
                var certMoq = new Moq.Mock<MoqX509Certificate2>();
                certMoq.Setup(c => c.MoqNotBefore).Returns(tp.Start);
                certMoq.Setup(c => c.MoqNotAfter).Returns(tp.End);

                var cert = certMoq.Object;
                var scts = new Dictionary<string, SctVerificationResult>();

                var numScts = rand.Next(tp.SctsRequired);
                for (var i = 0; i < numScts; i++)
                    scts[i.ToString()] = SctVerificationResult.Valid(DateTime.UtcNow, Guid.NewGuid().ToString());

                for (var i = 0; i < 10; i++)
                    scts[(i + 100).ToString()] = SctVerificationResult.FailedVerification(DateTime.UtcNow, Guid.NewGuid().ToString());

                var result = new CtPolicyDefault().PolicyVerificationResult(cert, scts);

                Assert.That(tp.SctsRequired == result.MinSctCount, tp.Description);
                Assert.That(result.Result == CtResult.TooFewSctsTrusted, tp.Description);
            }
        }

        [Test]
        public void CorrectNumberOfSctsReturnsSuccessTrusted()
        {
            foreach (var tp in _testParams)
            {
                var certMoq = new Moq.Mock<MoqX509Certificate2>();
                certMoq.Setup(c => c.MoqNotBefore).Returns(tp.Start);
                certMoq.Setup(c => c.MoqNotAfter).Returns(tp.End);

                var cert = certMoq.Object;
                var scts = new Dictionary<string, SctVerificationResult>();

                for (var i = 0; i < tp.SctsRequired; i++)
                    scts[i.ToString()] = SctVerificationResult.Valid(DateTime.UtcNow, Guid.NewGuid().ToString());

                for (var i = 0; i < 10; i++)
                    scts[(i + 100).ToString()] = SctVerificationResult.FailedVerification(DateTime.UtcNow, Guid.NewGuid().ToString());

                var result = new CtPolicyDefault().PolicyVerificationResult(cert, scts);

                Assert.That(result.Result == CtResult.Trusted, tp.Description);
            }
        }

        private struct PolicyTestParams
        {
            public PolicyTestParams(string description, DateTime start, DateTime end, int sctsRequired)
            {
                Description = description;
                Start = start;
                End = end;
                SctsRequired = sctsRequired;
            }

            public string Description { get; }
            public DateTime Start { get; }
            public DateTime End { get; }
            public int SctsRequired { get; }
        }
    }
}
