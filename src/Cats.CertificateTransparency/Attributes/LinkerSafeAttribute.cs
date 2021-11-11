using System;

namespace Cats.CertificateTransparency.Attributes
{
    [AttributeUsage(AttributeTargets.All)]
    internal class LinkerSafeAttribute : Attribute
    {
        public LinkerSafeAttribute()
        {
        }
    }
}
