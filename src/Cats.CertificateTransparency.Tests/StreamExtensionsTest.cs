using Cats.CertificateTransparency.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;

namespace Cats.CertificateTransparency.Tests
{
    [TestClass]
    public class StreamExtensionsTest
    {
        [TestMethod]
        public void ReadWrite_Long()
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            var numOfBytes = 8;
            var value = new Random().Next();

            bw.WriteLong(value, numOfBytes);

            var arr = ms.ToArray();

            using var reader = new MemoryStream(arr);

            var result = reader.ReadLong(numOfBytes);

            Assert.AreEqual(value, result);
        }

        [TestMethod]
        public void ReadWrite_VariableLength()
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

            Assert.AreEqual(data.Length, result.Length);
            Assert.IsTrue(data.SequenceEqual(result));
        }
    }
}
