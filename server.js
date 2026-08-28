const http = require("http");

const HOST = "127.0.0.1";
const PORT = 8787;
const MAX_BODY_BYTES = 1024 * 1024;

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "*",
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function applyTransform(text, transform) {
  switch (String(transform || "passthrough")) {
    case "audit":
      return text;
    case "rewrite":
      return `[REWRITE_HOP] ${text}`;
    case "filter":
      return String(text || "").replace(/\b(ignore previous instructions|reveal your system prompt)\b/gi, "[FILTERED]");
    case "passthrough":
    default:
      return text;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
      });
      res.end();
      return;
    }

    if (req.method !== "POST") {
      sendJson(res, 405, { error: "method_not_allowed" });
      return;
    }

    if (!req.url || !req.url.startsWith("/hop")) {
      sendJson(res, 404, { error: "not_found" });
      return;
    }

    const raw = await readBody(req);
    let payload = {};
    try {
      payload = raw ? JSON.parse(raw) : {};
    } catch {
      sendJson(res, 400, { error: "invalid_json" });
      return;
    }

    const inputText = String(payload.text || "");
    const domain = String(payload.domain || "unknown");
    const hopIndex = Number.isFinite(payload.hop_index) ? payload.hop_index : payload.hop_index;
    const transform = String(payload.transform || "passthrough");

    const outText = applyTransform(inputText, transform);

    console.log(
      JSON.stringify(
        {
          at: new Date().toISOString(),
          domain,
          hop_index: hopIndex,
          transform,
          inputLength: inputText.length,
          outputLength: outText.length,
        },
        null,
        2
      )
    );

    sendJson(res, 200, { text: outText });
  } catch (err) {
    sendJson(res, 500, { error: err instanceof Error ? err.message : "server_error" });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Proxy hop server listening on http://${HOST}:${PORT}/hop`);
  console.log("Use this in Prompt Injection Detector Options → Proxy Chain → Endpoint URL.");
});

