using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Api
{
    public interface ILogListApi
    {
        Task<byte[]> GetLogListAsync(CancellationToken cancellationToken);
        Task<byte[]> GetLogListSignatureAsync(CancellationToken cancellationToken);
        Task<(byte[] list, byte[] sig)> GetLogListWithSigAsync(CancellationToken cancellationToken);
    }
}
