using System;

namespace Cats.CertificateTransparency.Models
{
    public interface ILog
    {
        string Description { get; set; }
        string Key { get; set; }
        ReadOnlyMemory<byte> KeyBytes { get; }
        string LogId { get; set; }
        int Mmd { get; set; }
        State State { get; set; }
        TemporalInterval TemporalInterval { get; set; }
        DateTime? ValidUntilUtc { get; }
    }
}