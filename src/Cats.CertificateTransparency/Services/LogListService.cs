using Cats.CertificateTransparency.Api;
using Cats.CertificateTransparency.Models;
using Newtonsoft.Json;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Services
{
    public class LogListService : ILogListService
    {
        private const string LogListRootKey = nameof(LogListService) + "_" + nameof(GetLogListRootAsync);
        private const string LogDictionaryKey = nameof(LogListService) + "_" + nameof(GetLogDictionaryAsync);

        private readonly ILogListApi _logListApi;
        private readonly ILogStoreService _logStoreService;

        public LogListService(
            ILogListApi logListApi,
            ILogStoreService logStoreService)
        {
            _logListApi = logListApi;
            _logStoreService = logStoreService;
        }

        public async Task<LogListRoot> GetLogListRootAsync(CancellationToken cancellationToken)
        {
            var logListRoot = default(LogListRoot);

            if (!_logStoreService.TryGetValue(LogListRootKey, out logListRoot))
            {
                var logListTask = _logListApi.GetLogListJson(cancellationToken)
                    .ContinueWith(t => t.Result.ReadAsByteArrayAsync());
                var logListSignatureTask = _logListApi.GetLogListSignature(cancellationToken)
                    .ContinueWith(t => t.Result.ReadAsByteArrayAsync());

                await Task.WhenAll(logListTask, logListSignatureTask).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                await Task.WhenAll(logListTask.Result, logListSignatureTask.Result).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();

                var logListBytes = logListTask.Result.Result;
                var logListSignatureBytes = logListSignatureTask.Result.Result;

                var isValid = VerifyGoogleSignature(logListBytes, logListSignatureBytes);

                if (!isValid)
                    throw new InvalidDataException("Log list failed signature verification!");

                logListRoot = Deserialise<LogListRoot>(logListBytes);

                if (logListRoot?.Operators != null)
                    _logStoreService.SetValue(LogListRootKey, logListRoot);
            }

            return logListRoot;            
        }

        public async Task<IDictionary<string, Log>> GetLogDictionaryAsync(CancellationToken cancellationToken)
        {
            var logDictionary = default(IDictionary<string, Log>);

            if (!_logStoreService.TryGetValue(LogDictionaryKey, out logDictionary))
            {
                var logListRoot = await GetLogListRootAsync(cancellationToken).ConfigureAwait(false);
                if (logListRoot?.Operators != null)
                {
                    logDictionary = logListRoot.ToDictionary();
                    if (logDictionary.Any())
                        _logStoreService.SetValue(LogDictionaryKey, logDictionary);
                }
            }

            return logDictionary ?? new Dictionary<string, Log>(0);
        }

        private static bool VerifyGoogleSignature(byte[] data, byte[] signature)
        {
            var signer = SignerUtilities.GetSigner(Constants.Sha256WithRsa);
            var pubKey = PublicKeyFactory.CreateKey(ReadPemPublicKey(Constants.GoogleLogListPublicKey));
            signer.Init(false, pubKey);
            signer.BlockUpdate(data, 0, data.Length);
            var isValid = signer.VerifySignature(signature);
            return isValid;
        }

        private static byte[] ReadPemPublicKey(string publicKey)
        {
            string encodedPublicKey = publicKey
                .Replace(Constants.BeginPublicKey, string.Empty)
                .Replace(Constants.EndPublicKey, string.Empty)
                .Trim();
            return Convert.FromBase64String(encodedPublicKey);
        }

        private static T Deserialise<T>(byte[] data) where T : class
        {
            using var stream = new MemoryStream(data);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            return JsonSerializer.Create().Deserialize(reader, typeof(T)) as T;
        }
    }
}
