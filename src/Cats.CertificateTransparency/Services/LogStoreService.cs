using System.Collections.Concurrent;

namespace Cats.CertificateTransparency.Services
{
    public class LogStoreService : ILogStoreService
    {
        private readonly ConcurrentDictionary<object, object> _cache = new ConcurrentDictionary<object, object>();

        public LogStoreService()
        {
        }

        public T GetValue<T>(object key)
        {
            if (key != null && _cache.TryGetValue(key, out var objValue) && objValue is T t)
                return t;

            return default;
        }

        public bool TryGetValue<T>(object key, out T value)
        {
            if (key != null && _cache.TryGetValue(key, out var objValue) && objValue is T t)
            {
                value = t;
                return true;
            }

            value = default;
            return false;
        }

        public bool ContainsKey(object key)
        {
            return _cache.ContainsKey(key);
        }

        public void SetValue<T>(object key, T value)
        {
            _cache.AddOrUpdate(key, value, (k, v) => value);
        }

        public void Remove(object key)
        {
            _cache.TryRemove(key, out _);
        }

        public void Clear()
        {
            _cache.Clear();
        }
    }
}
