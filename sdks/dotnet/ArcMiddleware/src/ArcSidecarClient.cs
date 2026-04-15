// ARC sidecar HTTP client for .NET.
//
// Communicates with the ARC Rust kernel running as a localhost sidecar.
// Sends evaluation requests over HTTP and returns signed receipts.

using System.Net.Http.Json;
using System.Text.Json;

namespace Backbay.Arc;

/// <summary>
/// Exception thrown when the ARC sidecar is unreachable or returns an error.
/// </summary>
public class ArcSidecarException : Exception
{
    public string Code { get; }
    public int? StatusCode { get; }

    public ArcSidecarException(string code, string message, int? statusCode = null)
        : base(message)
    {
        Code = code;
        StatusCode = statusCode;
    }
}

/// <summary>
/// ARC sidecar client. Sends evaluation requests to the Rust kernel.
/// </summary>
public class ArcSidecarClient : IDisposable
{
    public const string DefaultSidecarUrl = "http://127.0.0.1:9090";

    private readonly string _baseUrl;
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    public ArcSidecarClient(string? baseUrl = null, int timeoutSeconds = 5)
    {
        _baseUrl = (baseUrl ?? Environment.GetEnvironmentVariable("ARC_SIDECAR_URL") ?? DefaultSidecarUrl)
            .TrimEnd('/');
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(timeoutSeconds)
        };
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };
    }

    /// <summary>
    /// Evaluate an HTTP request against the ARC kernel.
    /// </summary>
    public async Task<EvaluateResponse> EvaluateAsync(ArcHttpRequest request, string? capabilityToken = null)
    {
        HttpResponseMessage response;
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/arc/evaluate")
            {
                Content = JsonContent.Create(request, options: _jsonOptions)
            };
            if (!string.IsNullOrWhiteSpace(capabilityToken))
            {
                message.Headers.Add("X-Arc-Capability", capabilityToken);
            }
            response = await _httpClient.SendAsync(message);
        }
        catch (Exception ex)
        {
            throw new ArcSidecarException(
                ArcErrorCodes.SidecarUnreachable,
                $"Failed to reach ARC sidecar at {_baseUrl}: {ex.Message}"
            );
        }

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            throw new ArcSidecarException(
                ArcErrorCodes.EvaluationFailed,
                $"Sidecar returned {(int)response.StatusCode}: {body}",
                (int)response.StatusCode
            );
        }

        var result = await response.Content.ReadFromJsonAsync<EvaluateResponse>(_jsonOptions);
        return result ?? throw new ArcSidecarException(
            ArcErrorCodes.EvaluationFailed,
            "Sidecar returned null response"
        );
    }

    /// <summary>
    /// Verify a receipt signature against the sidecar.
    /// </summary>
    public async Task<bool> VerifyReceiptAsync(HttpReceipt receipt)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync(
                $"{_baseUrl}/arc/verify",
                receipt,
                _jsonOptions
            );

            if (!response.IsSuccessStatusCode)
                return false;

            var result = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>(_jsonOptions);
            return result?.TryGetValue("valid", out var valid) == true && valid is JsonElement elem && elem.GetBoolean();
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Health check for the sidecar.
    /// </summary>
    public async Task<bool> HealthCheckAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync($"{_baseUrl}/arc/health");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}
