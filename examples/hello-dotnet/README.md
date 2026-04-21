# hello-dotnet

Minimal ASP.NET example using [`sdks/dotnet/ChioMiddleware`](../../sdks/dotnet/ChioMiddleware/).

## What It Demonstrates

- `GET /hello` and `POST /echo` behind the real ASP.NET Chio middleware
- deny without capability and allow with a trust-issued capability token
- receipt ids emitted on the response header path for governed requests

## Files

```text
README.md
HelloChio.csproj
Program.cs
openapi.yaml
policy.yaml
run.sh
smoke.sh
```

## Run

Start the app only:

```bash
./run.sh
```

Run the full end-to-end smoke flow:

```bash
./smoke.sh
```
