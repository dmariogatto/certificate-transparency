using System;

namespace Cats.CertificateTransparency.Services
{
    public interface ILogStoreService
    {
        T GetValue<T>(string key);
        bool TryGetValue<T>(string key, out T value);

        bool ContainsKey(string key);

        void SetValue<T>(string key, T value);

        void Remove(string key);
        void Clear();
    }
}
