# Certificate Transparency for .NET

C# .NET port of,

- [certificate-transparency-java](https://github.com/google/certificate-transparency-java)
- [babylonhealth/certificate-transparency-android](https://github.com/babylonhealth/certificate-transparency-android)

![Cats.CertificateTransparency Logo](https://github.com/dmariogatto/certificate-transparency/raw/main/logo.png)

Download : [Nuget Package](https://www.nuget.org/packages/Cats.CertificateTransparency)

```
    Install-Package Cats.CertificateTransparency
```

[Blog Post](https://dgatto.com/posts/2020/12/cats-certificate-transparency/)

The library is designed to be dependency injection friendly, every service class has a matching interfaces. However, to get things up and running quickly there is also a static `Instance` class which will construct a lazy singletons for both `ILogListService` and `CertificateTransparencyVerifier`.

If you want to provide a custom list of included and excluded domains to these static instances you must first call `Instance.InitDomains`. By default validation will be enabled for all TLS secured domains.

```csharp
Instance.InitDomains(new [] { "*.google.com", "microsoft.com" }, new [] { "nuget.org" });
```

## Examples

### Plain old .NET Framework

```csharp
var client = new HttpClient(new HttpClientHandler()
{
    ServerCertificateCustomValidationCallback = (request, certificate, chain, sslPolicyErrors) =>
    {
        var certificateChain = chain.ChainElements.OfType<X509ChainElement>().Select(i => i.Certificate).ToList();
        var certificateVerifier = Cats.CertificateTransparency.Instance.CertificateTransparencyVerifier;
        var result = certificateVerifier.IsValidAsync(request.RequestUri.Host, certificateChain, CancellationToken.None).Result;

        return result.IsValid;
    }
});
```

### Xamarin Android

```csharp
bool VerifyCtResult(string hostname, IList<DotNetX509Certificate> certificateChain, CtVerificationResult result)
{
    // any extra checks or logging you might want to add
    return result.IsValid;
}

// optionally pass in a function to manually handle the transparency result
var httpHandler = new Cats.CertificateTransparency.Android.CatsAndroidClientHandler(VerifyCtResult);
var client = new HttpClient(httpHandler);
```

### Xamarin iOS

There is currently no platform specific implementation for iOS. Certificate transparency is already enabled since iOS 12.1.1, however, it can be disabled per domain via a property list setting [NSRequiresCertificateTransparency](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nsexceptiondomains).

If you are keen you could use the `CertificateVerifier` to build your own `HttpClientHandler`, similar to the included Android implementation.

## Contributions

Any contributions are welcome! Especially extra test cases!
