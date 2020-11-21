using Cats.CertificateTransparency.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

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
    }
}
