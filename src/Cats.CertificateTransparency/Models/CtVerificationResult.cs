using System.Collections.Generic;

namespace Cats.CertificateTransparency.Models
{
    public sealed class CtVerificationResult
    {
        public static CtVerificationResult DisabledForHost(string host)
            => new CtVerificationResult(CtResult.DisabledForHost, $"Success: SCT not enabled for {host}");
        public static CtVerificationResult Trusted(IDictionary<string, SctVerificationResult> sctResults, int minimumTrustedScts)
            => new CtVerificationResult(CtResult.Trusted, "Success: SCT trusted logs", sctResults, minimumTrustedScts);
        public static CtVerificationResult InsecureConnection(string host)
           => new CtVerificationResult(CtResult.InsecureConnection, $"Success: SCT not enabled for insecure connection to {host}");
        public static CtVerificationResult NoCertificates()
           => new CtVerificationResult(CtResult.NoCertificates, "Failure: No certificates");
        public static CtVerificationResult LogServersFailed()
          => new CtVerificationResult(CtResult.LogServersFailed, $"Failure: Unable to load log servers");
        public static CtVerificationResult NoScts()
          => new CtVerificationResult(CtResult.NoScts, $"Failure: Certificate does not contain any SCTs");
        public static CtVerificationResult TooFewSctsTrusted(IDictionary<string, SctVerificationResult> sctResults, int trustedCount, int minimumTrustedScts)
          => new CtVerificationResult(CtResult.TooFewSctsTrusted, $"Failure: Too few trusted SCTs, expected {minimumTrustedScts}, got {trustedCount}", sctResults, minimumTrustedScts);

        public CtVerificationResult(CtResult result, string description, IDictionary<string, SctVerificationResult> sctResults, int minSctCount = -1)
        {
            Result = result;
            Description = description;
            SctResults = sctResults ?? new Dictionary<string, SctVerificationResult>(0);
            MinSctCount = minSctCount;
        }

        public CtVerificationResult(CtResult result, string description) : this (result, description, new Dictionary<string, SctVerificationResult>(0))
        {
        }

        public IDictionary<string, SctVerificationResult> SctResults { get; private set; }

        public CtResult Result { get; private set; }
        public string Description { get; private set; }

        public int MinSctCount { get; private set; }

        public bool IsValid =>
            Result == CtResult.Trusted ||
            Result == CtResult.DisabledForHost;
        public override string ToString() => Description;
    }
}
