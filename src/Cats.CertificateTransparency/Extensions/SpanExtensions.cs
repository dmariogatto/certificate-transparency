using System;
using System.IO;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class SpanExtensions
    {
        internal static long ReadLong(this ReadOnlySpan<byte> span, int byteCount, ref int pos)
        {
            if (byteCount > Constants.BytesInLong)
                throw new ArgumentOutOfRangeException(nameof(byteCount));

            var result = 0L;

            for (var i = 0; i < byteCount; i++)
            {
                result = (result << 8) | span[pos++];
            }

            return result;
        }

        internal static ReadOnlySpan<byte> ReadVariableLength(this ReadOnlySpan<byte> span, int maxLength, ref int pos)
        {
            var lenBytes = Constants.BytesToStoreValue(maxLength);
            var length = span.ReadLong(lenBytes, ref pos);

            if (length > span.Length - pos)
                throw new IOException("Incomplete data");

            var slice = span.Slice(pos, (int)length);
            pos += (int)length;

            return slice;
        }
    }
}
