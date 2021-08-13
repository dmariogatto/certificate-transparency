using Cats.CertificateTransparency.Models;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Services
{
    public interface ILogListService
    {
        bool HasLogList { get; }

        public Task<bool> LoadLogListAsync(CancellationToken cancellationToken);
        void ClearLogList();

        public Task<LogListRoot> GetLogListRootAsync(CancellationToken cancellationToken);
        public Task<IDictionary<string, Log>> GetLogDictionaryAsync(CancellationToken cancellationToken);
    }
}
