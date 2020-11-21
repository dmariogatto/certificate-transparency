using System;

namespace Cats.CertificateTransparency.Services
{
    public interface IHostnameValidator
    {
        public bool ValidateHost(string host);
    }
}
