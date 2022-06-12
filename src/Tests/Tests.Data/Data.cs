using Newtonsoft.Json;
using Org.BouncyCastle.Utilities.IO.Pem;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Tests
{
    public static class Data
    {
        public const string DATA_ROOT = "Tests.Data.testdata.";

        // Public log key
        public const string TEST_LOG_KEY = DATA_ROOT + "ct-server-key-public.pem";
        public const string TEST_LOG_KEY_RSA = DATA_ROOT + "rsa.ct-server-key-public-rsa.pem";
        public const string TEST_LOG_KEY_PILOT = DATA_ROOT + "google-ct-pilot-server-key-public.pem";
        public const string TEST_LOG_KEY_SKYDIVER = DATA_ROOT + "google-ct-skydiver-server-key-public.pem";
        public const string TEST_LOG_KEY_DIGICERT = DATA_ROOT + "digicert-ct-server-key-public.pem";

        // Root CA cert.
        public const string ROOT_CA_CERT = DATA_ROOT + "ca-cert.pem";

        // Ordinary cert signed by ca-cert, with SCT served separately.
        public const string TEST_CERT = DATA_ROOT + "test-cert.pem";
        public const string TEST_CERT_SCT = DATA_ROOT + "test-cert.proof";
        public const string TEST_CERT_SCT_RSA = DATA_ROOT + "rsa.test-cert-rsa.proof";

        // PreCertificate signed by ca-cert.
        public const string TEST_PRE_CERT = DATA_ROOT + "test-embedded-pre-cert.pem";
        public const string TEST_PRE_SCT = DATA_ROOT + "test-embedded-pre-cert.proof";
        public const string TEST_PRE_SCT_RSA = DATA_ROOT + "rsa.test-embedded-pre-cert-rsa.proof";

        // PreCertificate Signing cert, signed by ca-cert.pem
        public const string PRE_CERT_SIGNING_CERT = DATA_ROOT + "ca-pre-cert.pem";

        // PreCertificate signed by the PreCertificate Signing Cert above.
        public const string TEST_PRE_CERT_SIGNED_BY_PRECA_CERT = DATA_ROOT + "test-embedded-with-preca-pre-cert.pem";
        public const string TEST_PRE_CERT_PRECA_SCT = DATA_ROOT + "test-embedded-with-preca-pre-cert.proof";

        // intermediate CA cert signed by ca-cert
        public const string INTERMEDIATE_CA_CERT = DATA_ROOT + "intermediate-cert.pem";

        // Certificate signed by intermediate CA.
        public const string TEST_INTERMEDIATE_CERT = DATA_ROOT + "test-intermediate-cert.pem";
        public const string TEST_INTERMEDIATE_CERT_SCT = DATA_ROOT + "test-intermediate-cert.proof";

        public const string TEST_PRE_CERT_SIGNED_BY_INTERMEDIATE = DATA_ROOT + "test-embedded-with-intermediate-pre-cert.pem";
        public const string TEST_PRE_CERT_SIGNED_BY_INTERMEDIATE_SCT = DATA_ROOT + "test-embedded-with-intermediate-pre-cert.proof";

        public const string PRE_CERT_SIGNING_BY_INTERMEDIATE = DATA_ROOT + "intermediate-pre-cert.pem";
        public const string TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE = DATA_ROOT + "test-embedded-with-intermediate-preca-pre-cert.pem";
        public const string TEST_PRE_CERT_SIGNED_BY_PRECA_INTERMEDIATE_SCT = DATA_ROOT + "test-embedded-with-intermediate-preca-pre-cert.proof";
        public const string TEST_ROOT_CERTS = DATA_ROOT + "test-root-certs";
        public const string TEST_GITHUB_CHAIN = DATA_ROOT + "github-chain.pem";

        public const string TEST_LOG_LIST_JSON = DATA_ROOT + "loglist.log_list.json";
        public const string TEST_LOG_LIST_JSON_TOO_BIG = DATA_ROOT + "loglist.log_list_too_big.json";
        public const string TEST_LOG_LIST_JSON_VALID_UNTIL = DATA_ROOT + "loglist.log_list_valid_until.json";
        public const string TEST_LOG_LIST_JSON_INCOMPLETE = DATA_ROOT + "loglist.log_list_incomplete.json";
        public const string TEST_LOG_LIST_SIG = DATA_ROOT + "loglist.log_list.sig";
        public const string TEST_LOG_LIST_SIG_TOO_BIG = DATA_ROOT + "loglist.log_list_too_big.sig";

        public const string TEST_LOG_LIST_ZIP = DATA_ROOT + "loglist.log_list.zip";
        public const string TEST_LOG_LIST_ZIP_TOO_BIG = DATA_ROOT + "loglist.log_list_too_big.zip";

        public const string TEST_LOG_LIST_ZIP_JSON_MISSING = DATA_ROOT + "loglist.log_list_json_missing.zip";
        public const string TEST_LOG_LIST_ZIP_SIG_MISSING = DATA_ROOT + "loglist.log_list_sig_missing.zip";
        public const string TEST_LOG_LIST_ZIP_JSON_TOO_BIG = DATA_ROOT + "loglist.log_list_json_too_big.zip";
        public const string TEST_LOG_LIST_ZIP_SIG_TOO_BIG = DATA_ROOT + "loglist.log_list_sig_too_big.zip";

        public const string TEST_MITMPROXY_ROOT_CERT = DATA_ROOT + "mitmproxy-ca-cert.pem";
        public const string TEST_MITMPROXY_ATTACK_CHAIN = DATA_ROOT + "mitmproxy-attack-chain.pem";
        public const string TEST_MITMPROXY_ORIGINAL_CHAIN = DATA_ROOT + "mitmproxy-original-chain.pem";

        public const string TEN_CERTS_CHAIN = DATA_ROOT + "chaincleaner.ten-certs-chain.pem";
        public const string TEN_CERTS_ROOT_CERT = DATA_ROOT + "chaincleaner.ten-certs-root-cert.pem";

        public const string ELEVEN_CERTS_CHAIN = DATA_ROOT + "chaincleaner.eleven-certs-chain.pem";
        public const string ELEVEN_CERTS_ROOT_CERT = DATA_ROOT + "chaincleaner.eleven-certs-root-cert.pem";

        public const string SELF_SIGNED_ROOT_CERT = DATA_ROOT + "chaincleaner.self-signed-root-cert.pem";

        public static List<X509Certificate2> LoadCerts(params string[] certs)
        {
            return certs.SelectMany(c => LoadCerts(c)).ToList();
        }

        public static List<X509Certificate2> LoadCerts(string cert)
        {
            using var stream = GetResourceStream(cert);
            using var reader = new StreamReader(stream);

            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);

            var pemObjs = new List<PemObject>();
            while (pemReader.Reader.Peek() > -1)
            {
                var pemObj = pemReader.ReadPemObject();
                if (pemObj is not null)
                    pemObjs.Add(pemObj);
            }

            return pemObjs.Select(po => new X509Certificate2(po.Content)).ToList();
        }

        public static T LoadJson<T>(string path) where T : class
        {
            using var stream = GetResourceStream(path);
            return Deserialise<T>(stream);
        }

        private static Stream GetResourceStream(string name)
        {
            var assembly = typeof(Data).Assembly;
            return assembly.GetManifestResourceStream(name);
        }

        private static T Deserialise<T>(Stream stream) where T : class
        {
            using var reader = new StreamReader(stream, Encoding.UTF8);
            var jsonSettings = new JsonSerializerSettings() { DateTimeZoneHandling = DateTimeZoneHandling.Utc };
            return JsonSerializer.Create(jsonSettings).Deserialize(reader, typeof(T)) as T;
        }
    }
}
