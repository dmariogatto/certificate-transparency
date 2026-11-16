using Cats.CertificateTransparency.Models;
using NUnit.Framework;
using System.Linq;
using System.Text.Json;

namespace Tests
{
    [TestFixture]
    public class LogListRootTest
    {
        [TestCase(2147483647L)]
        [TestCase(3501950757L)] // Google 'Argon2026h2' final tree size, exceeds Int32.MaxValue
        [TestCase(long.MaxValue)]
        public void DeserializeReadonlyFinalTreeHeadTreeSize(long treeSize)
        {
            var json = $$"""
                {
                    "operators": [{
                        "logs": [{
                            "log_id": "test-log",
                            "state": {
                                "readonly": {
                                    "final_tree_head": {
                                        "tree_size": {{treeSize}}
                                    }
                                }
                            }
                        }]
                    }]
                }
                """;

            var logListRoot = JsonSerializer.Deserialize<LogListRoot>(json);
            var log = logListRoot.Operators.Single().Logs.Single();

            Assert.That(log.State.Readonly.FinalTreeHead.TreeSize, Is.EqualTo(treeSize));
        }
    }
}
