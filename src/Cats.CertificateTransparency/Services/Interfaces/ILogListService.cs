using Cats.CertificateTransparency.Models;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Services
{
    public interface ILogListService
    {
        bool HasLogList { get; }

        public ValueTask<bool> LoadLogListAsync(CancellationToken cancellationToken);
        void ClearLogList();

        public ValueTask<LogListRoot> GetLogListRootAsync(CancellationToken cancellationToken);
        public ValueTask<IDictionary<string, Log>> GetLogDictionaryAsync(CancellationToken cancellationToken);
    }
}
