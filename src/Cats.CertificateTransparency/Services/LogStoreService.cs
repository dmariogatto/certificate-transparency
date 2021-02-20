using System.Collections.Concurrent;

namespace Cats.CertificateTransparency.Services
{
    public class LogStoreService : ILogStoreService
    {
        private readonly ConcurrentDictionary<string, object> _cache = new ConcurrentDictionary<string, object>();

        public LogStoreService()
        {
        }

        public T GetValue<T>(string key)
        {
            if (key != null && _cache.TryGetValue(key, out var objValue) && objValue is T t)
                return t;

            return default;
        }

        public bool TryGetValue<T>(string key, out T value)
        {
            if (key != null && _cache.TryGetValue(key, out var objValue) && objValue is T t)
            {
                value = t;
                return true;
            }

            value = default;
            return false;
        }

        public bool ContainsKey(string key)
        {
            return _cache.ContainsKey(key);
        }

        public void SetValue<T>(string key, T value)
        {
            _cache.AddOrUpdate(key, value, (k, v) => value);
        }

        public void Remove(string key)
        {
            _cache.TryRemove(key, out _);
        }

        public void Clear()
        {
            _cache.Clear();
        }
    }
}
