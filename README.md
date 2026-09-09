# Certificate Transparency for .NET

C# .NET port of,

- [certificate-transparency-java](https://github.com/google/certificate-transparency-java)
- [babylonhealth/certificate-transparency-android](https://github.com/babylonhealth/certificate-transparency-android)

![Cats.CertificateTransparency Logo](https://github.com/dmariogatto/certificate-transparency/raw/main/logo.png)

[![](https://img.shields.io/nuget/v/Cats.CertificateTransparency.svg)](https://nuget.org/packages/Cats.CertificateTransparency)

```powershell
    Install-Package Cats.CertificateTransparency
```

[Blog Post](https://dgatto.com/posts/2020/12/cats-certificate-transparency/)

> [!WARNING]
> ## Google CT Log List
>
> By default, this library uses the Certificate Transparency log list published by Google for Chrome:
>
> `https://www.gstatic.com/ct/log_list/v3/`
>
> **This is not recommended for production use.**
>
> Google's CT log list endpoints are intended to support Chrome and are subject to Google's [Acceptable Use Policy](https://googlechrome.github.io/CertificateTransparency/log_lists.html). Google explicitly states that third-party CT enforcement libraries relying on these endpoints may break.
>
> Google can change the endpoint, format, schema, or availability of the log list at any time. Google is also actively [fingerprinting and restricting third-party access](https://groups.google.com/a/chromium.org/g/ct-policy/c/qY3aOKr5-sU).
>
> As a result, applications using the default Google log list may **stop working without any change to this library or the application**. This has already occurred for Android clients using a mobile `User-Agent`, and further breakage is likely.
>
> **For production applications, you should ideally maintain and host your own CT log list** rather than depending on Google's Chrome-specific infrastructure. This gives you control over the list, endpoint, schema and availability.
>
> If you continue to use Google's log list, treat it as an external dependency that Google can change or break at any time.

The library is designed to be dependency-injection friendly; every service class has a matching interface. However, to get things running quickly, there is also a static `Instance` class which constructs lazy singletons for both `ILogListService` and `CertificateTransparencyVerifier`.

If you want to provide a custom list of included and excluded domains to these static instances, call `Instance.InitDomains` first. By default, validation is enabled for all TLS-secured domains.

```csharp
Instance.InitDomains(new [] { "*.google.com", "microsoft.com" }, new [] { "nuget.org" });
```

## Examples

### .NET

```csharp
var client = new HttpClient(new HttpClientHandler()
{
    ServerCertificateCustomValidationCallback = (request, certificate, chain, sslPolicyErrors) =>
    {
        var certificateChain = chain.ChainElements.OfType<X509ChainElement>().Select(i => i.Certificate).ToList();
        var certificateVerifier = Cats.CertificateTransparency.Instance.CertificateTransparencyVerifier;
        var ctValueTask = certificateVerifier.IsValidAsync(request.RequestUri.Host, certificateChain, CancellationToken.None);

        var ctResult = ctValueTask.IsCompleted
            ? ctValueTask.Result
            : ctValueTask.AsTask().Result;

        return ctResult.IsValid;
    }
});
```

### Android

> [!IMPORTANT]
> **Android 16+ (API 36) should use the native Android Certificate Transparency implementation instead of this library.**
>
> See [Android's native CT enforcement](https://developer.android.com/privacy-and-security/security-config#CertificateTransparencySummary) and the default [Android CT policy](https://developer.android.com/privacy-and-security/certificate-transparency-policy).

For applications targeting **Android versions prior to Android 16**, the Android implementation can be used:

```csharp
bool VerifyCtResult(string hostname, IList<DotNetX509Certificate> certificateChain, CtVerificationResult result)
{
    // Fail open if the CT log list is unreachable.
    if (result == CtResult.LogServersFailed)
    {
        return true;
    }

    // Add any additional checks or logging here.
    return result.IsValid;
}

var httpHandler = new Cats.CertificateTransparency.CatsAndroidClientHandler(VerifyCtResult);
var client = new HttpClient(httpHandler);
```

### iOS

There is currently no platform specific implementation for iOS. Certificate transparency is already enabled since iOS 12.1.1, however, it can be disabled per domain via a property list setting [NSRequiresCertificateTransparency](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nsexceptiondomains).

If you are keen you could use the `CertificateVerifier` to build your own `HttpClientHandler`, similar to the included Android implementation.

## Log Lists

A CT log list contains the Certificate Transparency logs that are trusted for verification.

For production applications, **maintaining your own log list is recommended**. Your application then controls:

- Which CT logs are trusted.
- Where the log list is hosted.
- The availability of the log list.
- Updates to the log list.
- The format and schema used by your application.

Using Google's Chrome log lists is convenient but creates a dependency on infrastructure that is outside the control of this project. Google may change or restrict access to the list without notice, and **applications should expect the Chrome log lists to break eventually**.

If you maintain your own log list, configure the library to use it through the appropriate `ILogListService` implementation.

## Contributions

Any contributions are welcome! Especially extra test cases!
