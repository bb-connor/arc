import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { createApp } from "./server.mjs";

async function withServer(callback) {
  const app = createApp({ enableChio: false });
  const server = http.createServer(app);

  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    await callback(server);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  }
}

async function requestJson(server, method, path, payload) {
  return new Promise((resolve, reject) => {
    const address = server.address();
    if (address === null || typeof address === "string") {
      reject(new Error("server not listening"));
      return;
    }

    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const headers =
      body === undefined
        ? {}
        : {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(body).toString(),
          };

    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: address.port,
        path,
        method,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf-8");
          resolve({
            status: res.statusCode ?? 0,
            body: text.length === 0 ? null : JSON.parse(text),
          });
        });
      },
    );
    req.on("error", reject);
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

test("healthz route bypass shape", async () => {
  await withServer(async (server) => {
    const response = await requestJson(server, "GET", "/healthz");

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { status: "ok" });
  });
});

test("hello route returns no receipt without middleware", async () => {
  await withServer(async (server) => {
    const response = await requestJson(server, "GET", "/hello");

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
      message: "hello from express",
      receipt_id: null,
    });
  });
});

test("echo defaults count and reports raw body absence without middleware", async () => {
  await withServer(async (server) => {
    const response = await requestJson(server, "POST", "/echo", {
      message: "hello",
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
      message: "hello",
      count: 1,
      receipt_id: null,
      has_raw_body: false,
    });
  });
});

test("echo rejects non-object bodies", async () => {
  await withServer(async (server) => {
    const response = await requestJson(server, "POST", "/echo", ["hello"]);

    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: "body must be a JSON object" });
  });
});

test("echo rejects empty messages", async () => {
  await withServer(async (server) => {
    const response = await requestJson(server, "POST", "/echo", {
      message: "",
      count: 1,
    });

    assert.equal(response.status, 400);
    assert.deepEqual(response.body, {
      error: "message must be a non-empty string",
    });
  });
});

test("echo rejects coerced counts", async () => {
  await withServer(async (server) => {
    const response = await requestJson(server, "POST", "/echo", {
      message: "hello",
      count: "2",
    });

    assert.equal(response.status, 400);
    assert.deepEqual(response.body, {
      error: "count must be an integer greater than or equal to 1",
    });
  });
});

test("echo rejects extra fields", async () => {
  await withServer(async (server) => {
    const response = await requestJson(server, "POST", "/echo", {
      message: "hello",
      count: 1,
      admin: true,
    });

    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: "unexpected fields: admin" });
  });
});
