import Fastify from "fastify";
import { arc } from "@arc-protocol/fastify";

const fastify = Fastify({ logger: false });

await fastify.register(arc, {
  sidecarUrl: process.env["ARC_SIDECAR_URL"] ?? "http://127.0.0.1:9090",
  skip: ["/healthz"],
});

fastify.get("/healthz", async () => ({ status: "ok" }));

fastify.get("/hello", async (request) => ({
  message: "hello from fastify",
  receipt_id: request.arcResult?.receipt.id ?? null,
}));

fastify.post("/echo", async (request) => {
  const payload = request.body ?? {};
  return {
    ...(typeof payload === "object" && payload !== null ? payload : { payload }),
    receipt_id: request.arcResult?.receipt.id ?? null,
  };
});

const port = Number(process.env["HELLO_FASTIFY_PORT"] ?? "8012");
await fastify.listen({ host: "127.0.0.1", port });
