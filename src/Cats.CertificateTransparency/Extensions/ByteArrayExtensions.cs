using System;
using System.Text;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class ByteArrayExtensions
    {
        internal static string ToHexString(this ReadOnlySpan<byte> span)
        {
            var hex = new StringBuilder(span.Length * 2);
            foreach (var b in span) hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
