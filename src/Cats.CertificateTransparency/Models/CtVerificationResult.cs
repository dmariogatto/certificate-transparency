﻿using System.Collections.Generic;

namespace Cats.CertificateTransparency.Models
{
    public sealed class CtVerificationResult
    {
        public static CtVerificationResult DisabledForHost(string host)
            => new CtVerificationResult(CtResult.DisabledForHost, $"Success: SCT not enabled for {host}", null);
        public static CtVerificationResult Trusted(IDictionary<string, SctVerificationResult> sctResults)
            => new CtVerificationResult(CtResult.Trusted, "Success: SCT trusted logs", sctResults);
        public static CtVerificationResult InsecureConnection(string host)
           => new CtVerificationResult(CtResult.InsecureConnection, $"Success: SCT not enabled for insecure connection to {host}", null);
        public static CtVerificationResult NoCertificates()
           => new CtVerificationResult(CtResult.NoCertificates, "Failure: No certificates", null);
        public static CtVerificationResult LogServersFailed()
          => new CtVerificationResult(CtResult.LogServersFailed, $"Failure: Unable to load log servers", null);
        public static CtVerificationResult NoScts()
          => new CtVerificationResult(CtResult.NoScts, $"Failure: Certificate does not have any Signed Certificate Timestamps in it", null);
        public static CtVerificationResult TooFewSctsTrusted(IDictionary<string, SctVerificationResult> sctResults, int trustedCount, int minimumTrustedScts)
          => new CtVerificationResult(CtResult.TooFewSctsTrusted, $"Failure: Too few trusted SCTs, expected {minimumTrustedScts}, got {trustedCount}", sctResults);
        
        public CtVerificationResult(CtResult result, string description, IDictionary<string, SctVerificationResult> sctResults)
        {
            Result = result;
            Description = description;
            SctResults = sctResults ?? new Dictionary<string, SctVerificationResult>(0);
        }

        public IDictionary<string, SctVerificationResult> SctResults { get; private set; }

        public CtResult Result { get; private set; }
        public string Description { get; private set; }

        public bool IsValid =>
            Result == CtResult.Trusted ||
            Result == CtResult.DisabledForHost;
        public override string ToString() => Description;
    }
}
