using System;
using System.IO;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class SpanExtensions
    {
        internal static long ReadLong(this Span<byte> span, int bytesToRead, ref int position)
        {
            if (bytesToRead > Constants.BytesInLong)
                throw new ArgumentOutOfRangeException(nameof(bytesToRead), $"Cannot read long of length {bytesToRead} bytes");

            var result = 0L;

            for (var i = 0; i < bytesToRead; i++)
            {
                var readVal = span[position++];
                result = (result << Constants.BitsInByte) | readVal;
            }

            return result;
        }

        internal static Span<byte> ReadVariableLength(this Span<byte> span, int maxDataValue, ref int position)
        {
            var bytesForDataLength = Constants.BytesToStoreValue(maxDataValue);
            var dataLength = ReadLong(span, bytesForDataLength, ref position);

            var data = span.Slice(position, (int)dataLength);
            position += data.Length;

            if (data.Length != dataLength) throw new IOException($"Incomplete data. Expected {dataLength} bytes, got {span.Length}");

            return data;
        }
    }
}
