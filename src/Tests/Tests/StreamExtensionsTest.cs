using Cats.CertificateTransparency.Extensions;
using NUnit.Framework;
using System;
using System.IO;
using System.Linq;

namespace Tests
{
    [TestFixture]
    public class StreamExtensionsTest
    {
        [Test]
        public void ReadWriteLong()
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            var numOfBytes = 8;
            var value = new Random().Next();

            bw.WriteLong(value, numOfBytes);

            var arr = ms.ToArray();

            using var reader = new MemoryStream(arr);

            var result = reader.ReadLong(numOfBytes);

            Assert.That(value == result);
        }

        [Test]
        public void ReadWriteVariableLength()
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

            var arr = ms.ToArray();

            using var reader = new MemoryStream(arr);

            var result = reader.ReadVariableLength(maxLength);

            Assert.That(data.Length == result.Length);
            Assert.That(data.SequenceEqual(result));
        }
    }
}
