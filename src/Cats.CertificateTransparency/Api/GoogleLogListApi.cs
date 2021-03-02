using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Api
{
    public class GoogleLogListApi : ILogListApi
    {
        private readonly string _googleLogListUrl;
        private readonly HttpClient _httpClient;

        public GoogleLogListApi(string baseUrl)
        {
            _googleLogListUrl = baseUrl;
            _httpClient = new HttpClient()
            {
                BaseAddress = new Uri(_googleLogListUrl)
            };
        }

        public async Task<byte[]> GetLogListAsync(CancellationToken cancellationToken)
        {
            using var msg = new HttpRequestMessage(HttpMethod.Get, "log_list.json");
            msg.Headers.Add("Cache-Control", "no-cache");
            msg.Headers.Add("Max-Size", "1048576");

            var result = await _httpClient.SendAsync(msg, cancellationToken).ConfigureAwait(false);
            result.EnsureSuccessStatusCode();

            return await result.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }

        public async Task<byte[]> GetLogListSignatureAsync(CancellationToken cancellationToken)
        {
            using var msg = new HttpRequestMessage(HttpMethod.Get, "log_list.sig");
            msg.Headers.Add("Cache-Control", "no-cache");
            msg.Headers.Add("Max-Size", "512");

            var result = await _httpClient.SendAsync(msg, cancellationToken).ConfigureAwait(false);
            result.EnsureSuccessStatusCode();

            return await result.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }

        public async Task<(byte[], byte[])> GetLogListWithSigAsync(CancellationToken cancellationToken)
        {
            using var msg = new HttpRequestMessage(HttpMethod.Get, "log_list.zip");
            msg.Headers.Add("Cache-Control", "no-cache");
            msg.Headers.Add("Max-Size", "2097152");

            var result = await _httpClient.SendAsync(msg, cancellationToken).ConfigureAwait(false);
            result.EnsureSuccessStatusCode();

            using var stream = await result.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, false);

            if (archive.Entries.Count != 2)
                throw new InvalidOperationException($"Expected 2 files from log list zip, got {archive.Entries.Count}");

            var logListEntry = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".json"))
                ?? throw new InvalidDataException($"Could not find log list json entry");

            var logListSigEntry = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".sig"))
                ?? throw new InvalidDataException($"Could not find log list signature entry");

            using var logListStream = logListEntry.Open();
            using var logListSigStream = logListSigEntry.Open();
            using var listMs = new MemoryStream();
            using var sigMs = new MemoryStream();

            await Task.WhenAll(
                logListStream.CopyToAsync(listMs, cancellationToken),
                logListSigStream.CopyToAsync(sigMs, cancellationToken)).ConfigureAwait(false);

            return (listMs.ToArray(), sigMs.ToArray());
        }
    }
}
