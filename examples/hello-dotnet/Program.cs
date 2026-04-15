using Backbay.Arc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddArcProtection();

var app = builder.Build();
app.UseArcProtection();

app.MapGet("/healthz", () => Results.Json(new { status = "ok" }));

app.MapGet("/hello", () => Results.Json(new { message = "hello from dotnet" }));

app.MapPost("/echo", (EchoRequest payload) =>
    Results.Json(new
    {
        message = payload.Message,
        count = payload.Count,
    }));

app.Run();

internal sealed record EchoRequest(string Message, int Count = 1);

