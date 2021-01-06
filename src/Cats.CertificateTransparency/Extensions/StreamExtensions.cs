using System;
using System.IO;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class StreamExtensions
    {
        internal static long ReadLong(this Stream stream, int numberOfBytes)
        {
            if (numberOfBytes > Constants.BitsInByte)
                throw new ArgumentOutOfRangeException(nameof(numberOfBytes), $"Cannot read long of length {numberOfBytes} bytes");

            var result = 0L;

            for (var i = 0; i < numberOfBytes; i++)
            {
                var readVal = stream.ReadByte();
                if (readVal < 0) throw new IOException($"Missing length bytes: Expected {numberOfBytes}, got {i}");
                result = (result << Constants.BitsInByte) | (uint)readVal;
            }

            return result;
        }

        internal static byte[] ReadVariableLength(this Stream stream, int maxDataLength)
        {
            var bytesForDataLength = BytesToStoreValue(maxDataLength);
            var dataLength = ReadLong(stream, bytesForDataLength);

            var data = new byte[dataLength];
            var readBytes = stream.Read(data, 0, (int)dataLength);

            if (readBytes != dataLength) throw new IOException($"Incomplete data. Expected {dataLength} bytes, got {readBytes}");

            return data;
        }

        internal static void WriteLong(this BinaryWriter writer, long value, int numberOfBytes)
        {
            if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));
            if (value > Math.Pow(256, numberOfBytes)) throw new InvalidOperationException($"Value {value} cannot be stored in {numberOfBytes} bytes");

            var numberOfBytesRemaining = numberOfBytes;
            while (numberOfBytesRemaining > 0)
            {
                var shiftBy = (numberOfBytesRemaining - 1) * Constants.BitsInByte;
                var mask = (long)0xff << shiftBy;
                var byteToWrite = (byte)((value & mask) >> shiftBy);
                writer.Write(byteToWrite);
                numberOfBytesRemaining--;
            }
        }

        internal static void WriteVariableLength(this BinaryWriter writer, byte[] data, int maxDataLength)
        {
            if (data.Length > maxDataLength) throw new ArgumentOutOfRangeException($"Length {data.Length} is greater than max data length {maxDataLength}");

            var bytesForDataLength = BytesToStoreValue(maxDataLength);
            writer.WriteLong(data.Length, bytesForDataLength);
            writer.Write(data, 0, data.Length);
        }

        private static int BytesToStoreValue(int value)
        {
            if (value < 0) throw new ArgumentOutOfRangeException(nameof(value), "Cannot be negative");

            var numBytes = 0;
            var local = value;

            while (local > 0)
            {
                local >>= Constants.BitsInByte;
                numBytes++;
            }

            return numBytes;
        }
    }
}
