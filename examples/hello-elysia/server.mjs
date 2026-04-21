import http from "node:http";
import { Elysia } from "elysia";
import { chio } from "@chio-protocol/elysia";

const port = Number(process.env["HELLO_ELYSIA_PORT"] ?? "8014");

const app = new Elysia()
  .use(
    chio({
      sidecarUrl: process.env["CHIO_SIDECAR_URL"] ?? "http://127.0.0.1:9090",
      skip: ["/healthz"],
    }),
  )
  .get("/healthz", () => ({ status: "ok" }))
  .get("/hello", () => ({ message: "hello from elysia" }))
  .post("/echo", ({ body }) => {
    const payload = typeof body === "object" && body !== null ? body : {};
    return payload;
  });

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? `127.0.0.1:${port}`}`);
  const bodyChunks = [];
  for await (const chunk of req) {
    bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const request = new Request(url, {
    method: req.method ?? "GET",
    headers: req.headers,
    body:
      bodyChunks.length > 0
        ? Buffer.concat(bodyChunks)
        : undefined,
  });

  const response = await app.handle(request);
  res.statusCode = response.status;
  response.headers.forEach((value, key) => {
    res.setHeader(key, value);
  });
  const responseBody = Buffer.from(await response.arrayBuffer());
  res.end(responseBody);
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`hello-elysia listening on http://127.0.0.1:${port}\n`);
});
