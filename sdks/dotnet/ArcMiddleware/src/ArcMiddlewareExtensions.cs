// ASP.NET Core middleware for ARC capability validation and receipt signing.
//
// Intercepts all HTTP requests, extracts caller identity, sends evaluation
// requests to the ARC sidecar kernel, and either allows the request to
// proceed with a signed receipt or returns a structured deny response.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Backbay.Arc;

/// <summary>
/// Configuration options for the ARC middleware.
/// </summary>
public class ArcMiddlewareOptions
{
    /// <summary>
    /// Base URL of the ARC sidecar kernel. Defaults to ARC_SIDECAR_URL env var
    /// or "http://127.0.0.1:9090".
    /// </summary>
    public string SidecarUrl { get; set; } =
        Environment.GetEnvironmentVariable("ARC_SIDECAR_URL") ?? "http://127.0.0.1:9090";

    /// <summary>
    /// HTTP timeout for sidecar calls in seconds. Default: 5.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 5;

    /// <summary>
    /// Behavior when sidecar is unreachable: "deny" (fail-closed, default)
    /// or "allow" (fail-open).
    /// </summary>
    public string OnSidecarError { get; set; } = "deny";

    /// <summary>
    /// Custom identity extractor. Defaults to header-based extraction.
    /// </summary>
    public IdentityExtractorDelegate? IdentityExtractor { get; set; }

    /// <summary>
    /// Custom route pattern resolver. Maps (method, path) to a route pattern.
    /// Defaults to returning the raw path.
    /// </summary>
    public Func<string, string, string>? RouteResolver { get; set; }
}

/// <summary>
/// ASP.NET Core middleware that protects HTTP APIs with ARC evaluation.
/// </summary>
public class ArcProtectMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ArcSidecarClient _client;
    private readonly ArcMiddlewareOptions _options;
    private readonly IdentityExtractorDelegate _identityExtractor;
    private readonly Func<string, string, string> _routeResolver;
    private readonly ILogger<ArcProtectMiddleware> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    private static readonly HashSet<string> ValidMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    };

    public ArcProtectMiddleware(
        RequestDelegate next,
        IOptions<ArcMiddlewareOptions> options,
        ILogger<ArcProtectMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _client = new ArcSidecarClient(_options.SidecarUrl, _options.TimeoutSeconds);
        _identityExtractor = _options.IdentityExtractor ?? ArcIdentityExtractor.DefaultExtract;
        _routeResolver = _options.RouteResolver ?? ((_, path) => path);
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        var method = request.Method.ToUpperInvariant();

        if (!ValidMethods.Contains(method))
        {
            await WriteJsonError(context, 405, new ArcErrorResponse
            {
                Error = ArcErrorCodes.EvaluationFailed,
                Message = $"unsupported HTTP method: {method}",
            });
            return;
        }

        // Extract caller identity.
        var caller = _identityExtractor(request);

        // Resolve route pattern.
        var routePattern = _routeResolver(method, request.Path.Value ?? "/");

        // Hash request body.
        string? bodyHash = null;
        long bodyLength = 0;
        if (request.ContentLength.HasValue && request.ContentLength.Value > 0)
        {
            request.EnableBuffering();
            var bodyBytes = new byte[request.ContentLength.Value];
            var bytesRead = await request.Body.ReadAsync(bodyBytes);
            bodyLength = bytesRead;
            if (bytesRead > 0)
            {
                bodyHash = ArcIdentityExtractor.Sha256Hex(
                    Encoding.UTF8.GetString(bodyBytes, 0, bytesRead)
                );
            }
            request.Body.Position = 0;
        }

        // Extract selected headers.
        var headers = new Dictionary<string, string>();
        foreach (var headerName in new[] { "content-type", "content-length", "x-arc-capability" })
        {
            if (request.Headers.TryGetValue(headerName, out var values))
            {
                var val = values.FirstOrDefault();
                if (val != null)
                    headers[headerName] = val;
            }
        }

        // Build ARC HTTP request.
        var arcRequest = new ArcHttpRequest
        {
            RequestId = Guid.NewGuid().ToString(),
            Method = method,
            RoutePattern = routePattern,
            Path = request.Path.Value ?? "/",
            Query = request.Query.ToDictionary(q => q.Key, q => q.Value.FirstOrDefault() ?? ""),
            Headers = headers,
            Caller = caller,
            BodyHash = bodyHash,
            BodyLength = bodyLength,
            CapabilityId = request.Headers.TryGetValue("X-Arc-Capability", out var capValues)
                ? capValues.FirstOrDefault()
                : null,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };

        // Evaluate against sidecar.
        EvaluateResponse result;
        try
        {
            result = await _client.EvaluateAsync(arcRequest);
        }
        catch (ArcSidecarException ex)
        {
            if (_options.OnSidecarError == "allow")
            {
                await _next(context);
                return;
            }
            _logger.LogError(ex, "ARC sidecar error");
            await WriteJsonError(context, 502, new ArcErrorResponse
            {
                Error = ArcErrorCodes.SidecarUnreachable,
                Message = $"ARC sidecar error: {ex.Message}",
            });
            return;
        }
        catch (Exception ex)
        {
            if (_options.OnSidecarError == "allow")
            {
                await _next(context);
                return;
            }
            _logger.LogError(ex, "ARC sidecar error");
            await WriteJsonError(context, 502, new ArcErrorResponse
            {
                Error = ArcErrorCodes.SidecarUnreachable,
                Message = $"ARC sidecar error: {ex.Message}",
            });
            return;
        }

        // Attach receipt ID.
        context.Response.Headers["X-Arc-Receipt-Id"] = result.Receipt.Id;

        // Check verdict.
        if (result.Verdict.IsDenied())
        {
            var status = result.Verdict.HttpStatus > 0 ? result.Verdict.HttpStatus : 403;
            await WriteJsonError(context, status, new ArcErrorResponse
            {
                Error = ArcErrorCodes.AccessDenied,
                Message = result.Verdict.Reason ?? "denied",
                ReceiptId = result.Receipt.Id,
                Suggestion = "provide a valid capability token in the X-Arc-Capability header",
            });
            return;
        }

        // Request allowed -- forward to next middleware.
        await _next(context);
    }

    private async Task WriteJsonError(HttpContext context, int statusCode, ArcErrorResponse error)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(error, _jsonOptions);
    }
}

/// <summary>
/// Extension methods for registering ARC middleware.
/// </summary>
public static class ArcMiddlewareExtensions
{
    /// <summary>
    /// Add ARC middleware services to the dependency injection container.
    /// </summary>
    public static IServiceCollection AddArcProtection(
        this IServiceCollection services,
        Action<ArcMiddlewareOptions>? configure = null)
    {
        if (configure != null)
        {
            services.Configure(configure);
        }
        else
        {
            services.Configure<ArcMiddlewareOptions>(_ => { });
        }
        return services;
    }

    /// <summary>
    /// Use ARC protection middleware in the request pipeline.
    /// </summary>
    public static IApplicationBuilder UseArcProtection(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ArcProtectMiddleware>();
    }
}
