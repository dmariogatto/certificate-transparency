using System;
using System.IO;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class StreamExtensions
    {
        internal static long ReadLong(this Stream stream, int byteCount)
        {
            if (byteCount > Constants.BytesInLong)
                throw new ArgumentOutOfRangeException(nameof(byteCount), $"Cannot read long of length {byteCount} bytes");

            Span<byte> buffer = stackalloc byte[8];
            var slice = buffer[..byteCount];

            Fill(stream, slice);

            var result = 0L;
            for (var i = 0; i < byteCount; i++)
            {
                result = (result << 8) | slice[i];
            }

            return result;
        }

        internal static Span<byte> ReadVariableLength(this Stream stream, int maxLength)
        {
            var lenBytes = Constants.BytesToStoreValue(maxLength);
            var length = stream.ReadLong(lenBytes);

            var result = new byte[length];

            Fill(stream, result);

            return result;
        }

        internal static void WriteLong(this Stream stream, long value, int byteCount)
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(value));

            if (byteCount < 8 && value >= (1L << (byteCount * 8)))
                throw new InvalidOperationException($"Value {value} cannot be stored in {byteCount} bytes");

            Span<byte> buffer = stackalloc byte[8];

            for (int i = byteCount - 1; i >= 0; i--)
            {
                buffer[i] = (byte)value;
                value >>= 8;
            }

            stream.Write(buffer[..byteCount]);
        }

        internal static void WriteVariableLength(this Stream stream, ReadOnlySpan<byte> data, int maxLength)
        {
            if (data.Length > maxLength)
                throw new ArgumentOutOfRangeException($"Length {data.Length} is greater than max length {maxLength}");

            var lenBytes = Constants.BytesToStoreValue(maxLength);

            stream.WriteLong(data.Length, lenBytes);
            stream.Write(data);
        }

        private static void Fill(Stream stream, Span<byte> buffer)
        {
            var total = 0;

            while (total < buffer.Length)
            {
                var read = stream.Read(buffer[total..]);
                if (read <= 0)
                    throw new IOException("Unexpected EOF");

                total += read;
            }
        }
    }
}
