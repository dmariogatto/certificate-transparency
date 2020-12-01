using System.Text;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class ByteArrayExtensions
    {
        internal static string ToHexString(this byte[] array)
        {
            var hex = new StringBuilder(array.Length * 2);
            foreach (var b in array) hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
