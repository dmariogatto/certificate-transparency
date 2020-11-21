using Refit;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Api
{
    public interface ILogListApi
    {
        [Get("/log_list.json")]
        [Headers("Cache-Control: no-cache", "Max-Size: 1048576")]
        Task<HttpContent> GetLogListJson(CancellationToken cancellationToken);

        [Get("/log_list.sig")]
        [Headers("Cache-Control: no-cache", "Max-Size: 512")]
        Task<HttpContent> GetLogListSignature(CancellationToken cancellationToken);

        [Get("/log_list.zip")]
        [Headers("Cache-Control: no-cache", "Max-Size: 2097152")]
        Task<HttpContent> GetLogListZip(CancellationToken cancellationToken);
    }
}
