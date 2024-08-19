using Cats.CertificateTransparency.Extensions;
using NUnit.Framework;
using System;
using System.IO;
using System.Linq;

namespace Tests
{
    [TestFixture]
    public class SpanExtensionsTest
    {
        [Test]
        public void ReadLong()
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            var numOfBytes = 8;
            var value = new Random().Next();

            bw.WriteLong(value, numOfBytes);

            var span = ms.ToArray().AsSpan();
            var position = 0;

            var result = span.ReadLong(numOfBytes, ref position);
            Assert.That(value == result);
        }

        [Test]
        public void ReadVariableLength()
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            var rand = new Random();

            var minLength = 256;
            var maxLength = 4096;

            var dataLength = rand.Next(minLength, maxLength);
            var data = new byte[dataLength];
            for (var i = 0; i < dataLength; i++)
                data[i] = (byte)rand.Next(0, 255);

            bw.WriteVariableLength(data, maxLength);

            var span = ms.ToArray().AsSpan();
            var position = 0;

            var result = span.ReadVariableLength(maxLength, ref position);

            Assert.That(data.Length == result.Length);
            Assert.That(data.SequenceEqual(result.ToArray()));
        }
    }
}
