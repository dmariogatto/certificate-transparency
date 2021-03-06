﻿using Cats.CertificateTransparency.Models;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Services
{
    public interface ICertificateTransparencyVerifier
    {
        public ValueTask<CtVerificationResult> IsValidAsync(string hostname, IList<X509Certificate2> chain, CancellationToken cancellationToken);
        public ValueTask<CtVerificationResult> IsValidAsync(IList<X509Certificate2> chain, CancellationToken cancellationToken);
    }
}
