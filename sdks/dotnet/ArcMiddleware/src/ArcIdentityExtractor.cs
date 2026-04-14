// Default identity extraction from HTTP request headers.
//
// Mirrors the Rust extract_caller logic in arc-api-protect.
// Extracts caller identity from Authorization headers, API keys, and cookies.

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Backbay.Arc;

/// <summary>
/// Delegate for extracting caller identity from an HTTP request.
/// </summary>
public delegate CallerIdentity IdentityExtractorDelegate(HttpRequest request);

/// <summary>
/// Default identity extraction utilities.
/// </summary>
public static class ArcIdentityExtractor
{
    /// <summary>
    /// Compute SHA-256 hex digest of a string.
    /// </summary>
    public static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexStringLower(bytes);
    }

    /// <summary>
    /// Default identity extractor. Checks headers in order:
    /// 1. Authorization: Bearer token
    /// 2. X-API-Key header
    /// 3. Cookie header
    /// 4. Anonymous fallback
    /// </summary>
    public static CallerIdentity DefaultExtract(HttpRequest request)
    {
        // 1. Bearer token
        var auth = request.Headers.Authorization.FirstOrDefault();
        if (auth != null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = auth["Bearer ".Length..];
            var tokenHash = Sha256Hex(token);
            return new CallerIdentity
            {
                Subject = $"bearer:{tokenHash[..16]}",
                AuthMethod = AuthMethod.Bearer(tokenHash),
            };
        }

        // 2. API key
        foreach (var keyHeader in new[] { "X-API-Key", "X-Api-Key", "x-api-key" })
        {
            if (request.Headers.TryGetValue(keyHeader, out var keyValues))
            {
                var keyValue = keyValues.FirstOrDefault();
                if (!string.IsNullOrEmpty(keyValue))
                {
                    var keyHash = Sha256Hex(keyValue);
                    return new CallerIdentity
                    {
                        Subject = $"apikey:{keyHash[..16]}",
                        AuthMethod = AuthMethod.ApiKey(keyHeader, keyHash),
                    };
                }
            }
        }

        // 3. Cookie
        if (request.Cookies.Count > 0)
        {
            var cookie = request.Cookies.First();
            var cookieHash = Sha256Hex(cookie.Value);
            return new CallerIdentity
            {
                Subject = $"cookie:{cookieHash[..16]}",
                AuthMethod = new AuthMethod
                {
                    Method = "cookie",
                    CookieName = cookie.Key,
                    CookieHash = cookieHash,
                },
            };
        }

        // 4. Anonymous
        return CallerIdentity.CreateAnonymous();
    }
}
