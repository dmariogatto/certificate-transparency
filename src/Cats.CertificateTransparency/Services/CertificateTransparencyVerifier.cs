using Cats.CertificateTransparency.Extensions;
using Cats.CertificateTransparency.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Services
{
    public class CertificateTransparencyVerifier : ICertificateTransparencyVerifier
    {
        private readonly IHostnameValidator _hostnameValidator;
        private readonly ILogListService _logListService;
        private readonly ICtPolicy _ctPolicy;

        public CertificateTransparencyVerifier(
            IHostnameValidator hostnameValidator,
            ILogListService logListService,
            ICtPolicy ctPolicy)
        {
            _hostnameValidator = hostnameValidator;
            _logListService = logListService;
            _ctPolicy = ctPolicy;
        }

        public async ValueTask<CtVerificationResult> IsValidAsync(string hostname, IList<X509Certificate2> chain, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(hostname)) throw new ArgumentNullException(nameof(hostname));

            if (_hostnameValidator.ValidateHost(hostname))
            {
                return await IsValidAsync(chain, cancellationToken).ConfigureAwait(false);
            }

            return CtVerificationResult.DisabledForHost();
        }

        public async ValueTask<CtVerificationResult> IsValidAsync(IList<X509Certificate2> chain, CancellationToken cancellationToken)
        {
            if (chain?.Any() != true)
                return CtVerificationResult.NoCertificates();

            var leaf = chain.First();
            var scts = leaf.GetSignedCertificateTimestamps();

            if (scts?.Any() != true)
                return CtVerificationResult.NoScts();

            var logDictionary = await _logListService.GetLogDictionaryAsync(cancellationToken).ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            if (logDictionary?.Any() != true)
                return CtVerificationResult.LogServersFailed();

            var sctResults = scts.Select(sct =>
                    logDictionary.TryGetValue(sct.LogIdBase64, out var log)
                    ? (sct.LogIdBase64, sct.VerifySignature(log, chain))
                    : (sct.LogIdBase64, SctVerificationResult.NoTrustedLogServerFound(sct.TimestampUtc)))
                .ToDictionary(t => t.LogIdBase64, t => t.Item2);

            return _ctPolicy.PolicyVerificationResult(leaf, sctResults);
        }
    }
}
