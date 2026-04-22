using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Backbay.Chio;
using Xunit;

namespace Backbay.Chio.Tests;

public class ChioMiddlewareCapabilityTests
{
    [Fact]
    public async Task QueryCapabilityTokenIsForwardedToSidecar()
    {
        var port = GetFreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var observedCapability = "";
        var sidecarTask = Task.Run(async () =>
        {
            var requestContext = await listener.GetContextAsync();
            observedCapability = requestContext.Request.Headers["X-Chio-Capability"] ?? "";

            var responseJson = """
            {
              "verdict": { "verdict": "allow" },
              "receipt": {
                "id": "receipt-query-capability",
                "request_id": "req-1",
                "route_pattern": "/pets",
                "method": "GET",
                "caller_identity_hash": "hash",
                "verdict": { "verdict": "allow" },
                "evidence": [],
                "response_status": 200,
                "timestamp": 1700000000,
                "content_hash": "content",
                "policy_hash": "policy",
                "kernel_key": "kernel",
                "signature": "signature"
              },
              "evidence": []
            }
            """;

            var bytes = Encoding.UTF8.GetBytes(responseJson);
            requestContext.Response.StatusCode = 200;
            requestContext.Response.ContentType = "application/json";
            await requestContext.Response.OutputStream.WriteAsync(bytes);
            requestContext.Response.Close();
        });

        var middleware = new ChioProtectMiddleware(
            next: context =>
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return Task.CompletedTask;
            },
            options: Options.Create(new ChioMiddlewareOptions
            {
                SidecarUrl = $"http://127.0.0.1:{port}",
            }),
            logger: NullLogger<ChioProtectMiddleware>.Instance
        );

        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/pets";
        context.Request.QueryString = new QueryString("?chio_capability=query-token");

        await middleware.InvokeAsync(context);
        await sidecarTask;

        Assert.Equal("query-token", observedCapability);
        Assert.Equal("receipt-query-capability", context.Response.Headers["X-Chio-Receipt-Id"]);
        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);
    }

    [Fact]
    public async Task FailOpenPassthroughDoesNotAttachSyntheticReceiptHeader()
    {
        ChioPassthrough? observedPassthrough = null;
        var middleware = new ChioProtectMiddleware(
            next: context =>
            {
                observedPassthrough = context.Items[ChioContextKeys.Passthrough] as ChioPassthrough;
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return Task.CompletedTask;
            },
            options: Options.Create(new ChioMiddlewareOptions
            {
                SidecarUrl = "http://127.0.0.1:1",
                OnSidecarError = "allow",
                TimeoutSeconds = 1,
            }),
            logger: NullLogger<ChioProtectMiddleware>.Instance
        );

        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/pets";

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("X-Chio-Receipt-Id"));
        Assert.NotNull(observedPassthrough);
        Assert.Equal("allow_without_receipt", observedPassthrough!.Mode);
        Assert.Equal(ChioErrorCodes.SidecarUnreachable, observedPassthrough.Error);
    }

    private static int GetFreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
