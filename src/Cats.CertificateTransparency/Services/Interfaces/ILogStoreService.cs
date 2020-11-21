using System;

namespace Cats.CertificateTransparency.Services
{
    public interface ILogStoreService
    {
        T GetValue<T>(object key);
        bool TryGetValue<T>(object key, out T value);

        bool ContainsKey(object key);

        void SetValue<T>(object key, T value);

        void Remove(object key);
        void Clear();
    }
}
