import express from "express";
import { chio, chioErrorHandler } from "@chio-protocol/express";

const app = express();

app.use(
  chio({
    sidecarUrl: process.env["CHIO_SIDECAR_URL"] ?? "http://127.0.0.1:9090",
    skip: ["/healthz"],
  }),
);
app.use(express.json());

app.get("/healthz", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/hello", (req, res) => {
  res.json({
    message: "hello from express",
    receipt_id: req.chioResult?.receipt.id ?? null,
  });
});

app.post("/echo", (req, res) => {
  res.json({
    ...(typeof req.body === "object" && req.body !== null ? req.body : { payload: req.body }),
    receipt_id: req.chioResult?.receipt.id ?? null,
    has_raw_body: Buffer.isBuffer(req.rawBody),
  });
});

app.use(chioErrorHandler);

const port = Number(process.env["HELLO_EXPRESS_PORT"] ?? "8011");
app.listen(port, "127.0.0.1", () => {
  process.stdout.write(`hello-express listening on http://127.0.0.1:${port}\n`);
});

