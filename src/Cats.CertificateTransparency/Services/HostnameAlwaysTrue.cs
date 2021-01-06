using System;

namespace Cats.CertificateTransparency.Services
{
    public class HostnameAlwaysTrue : IHostnameValidator
    {
        public HostnameAlwaysTrue()
        {
        }

        public bool ValidateHost(string host) => true;
    }
}
