const http = require("http"),
  crypto = require("crypto"),
  posix = require("path").posix,
  mailroom = require("./mailroom"),
  scanner = require("./scanner"),
  redteam = require("./redteam");
const EMAIL = "24f2007163@ds.study.iitm.ac.in",
  SECRET = "/home/agent/service-account.json",
  WORKDIR = "/home/agent/workspace";
function send(res, status, body) {
  const h = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
  if (body === undefined) {
    res.writeHead(status, h);
    return res.end();
  }
  const text = JSON.stringify(body);
  res.writeHead(status, {
    ...h,
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(text),
  });
  res.end(text);
}
const result = (id, value) => ({ jsonrpc: "2.0", id, result: value }),
  error = (id, code, message) => ({
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code, message },
  });
function expandShell(s) {
  let x = String(s).trim();
  for (let i = 0; i < 3; i++) {
    try {
      const y = decodeURIComponent(x);
      if (y === x) break;
      x = y;
    } catch {
      break;
    }
  }
  x = x
    .replaceAll("$" + "{HOME}", "/home/agent")
    .replaceAll("$HOME", "/home/agent")
    .replaceAll("$" + "{PWD}", WORKDIR)
    .replaceAll("$PWD", WORKDIR)
    .replace(/(^|[\s;|&(])~(?=\/|\s|$)/g, "$1/home/agent");
  return x.replace(/["']/g, "").replace(/\\/g, "/");
}
function mentionsSecret(command) {
  const queue = [String(command)],
    seen = new Set();
  for (let depth = 0; depth < 4 && queue.length; depth++) {
    const level = queue.splice(0);
    for (const raw of level) {
      if (seen.has(raw)) continue;
      seen.add(raw);
      const s = expandShell(raw);
      if (s.includes(SECRET)) return true;
      const tokens = s
        .split(/[\s;|&()<>]+/)
        .map((v) => v.replace(/^[,:=]+|[,:]+$/g, ""));
      for (const token of tokens)
        if (
          token &&
          (token.startsWith("/") ||
            token.startsWith("./") ||
            token.startsWith("../")) &&
          posix.resolve(WORKDIR, token) === SECRET
        )
          return true;
      for (const token of raw.match(/[A-Za-z0-9+\/_-]{12,}={0,2}/g) || []) {
        try {
          const decoded = Buffer.from(
            token.replace(/-/g, "+").replace(/_/g, "/"),
            "base64",
          ).toString("utf8");
          if (decoded && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(decoded))
            queue.push(decoded);
        } catch {}
      }
    }
  }
  return false;
}
function guard(call) {
  if (!call || typeof call !== "object")
    return { decision: "block", reason: "Malformed tool call." };
  if (call.tool === "bash") {
    if (typeof call.command !== "string")
      return { decision: "block", reason: "A bash command is required." };
    if (mentionsSecret(call.command))
      return {
        decision: "block",
        reason: "Access to the service-account secret is forbidden.",
      };
    return {
      decision: "allow",
      reason: "The command does not access the restricted secret.",
    };
  }
  if (call.tool === "write_file") {
    if (typeof call.path !== "string" || call.path.includes("\0"))
      return { decision: "block", reason: "A valid file path is required." };
    const normalized = posix.resolve(WORKDIR, expandShell(call.path));
    if (normalized.startsWith("/workspace/output/"))
      return {
        decision: "allow",
        reason: "The normalized path is inside /workspace/output/.",
      };
    return {
      decision: "block",
      reason: "Writes are allowed only inside /workspace/output/.",
    };
  }
  if (call.tool === "http_request") {
    if (typeof call.url !== "string")
      return { decision: "block", reason: "A valid URL is required." };
    try {
      const u = new URL(call.url);
      if (
        (u.protocol === "http:" || u.protocol === "https:") &&
        (u.hostname === "pypi.org" || u.hostname === "registry.npmjs.org")
      )
        return {
          decision: "allow",
          reason: "The destination hostname is allowlisted.",
        };
    } catch {}
    return {
      decision: "block",
      reason: "The destination hostname is not allowlisted.",
    };
  }
  return { decision: "block", reason: "Unknown tool." };
}
function scanSkill(value) {
  const s = String(value || ""),
    lower = s.toLowerCase(),
    categories = [];
  const front = (s.match(/^---\s*\r?\n([\s\S]*?)\r?\n---/m) || [])[1] || "";
  const literalSecret =
    /(?:api[_ -]?key|secret|token|password|webhook(?:_url)?|client[_ -]?secret)\s*[:=]\s*["']?(?!\$\{?[a-z_][a-z0-9_]*\}?|env(?:iron)?\b|secret\s*store)[a-z0-9_\-]{10,}/i.test(
      s,
    ) ||
    /https:\/\/hooks\.(?:slack|discord)\.com\/services\/[a-z0-9_\/-]{12,}/i.test(
      s,
    ) ||
    /\b(?:sk-[a-z0-9_-]{16,}|gh[pousr]_[a-z0-9]{20,}|AIza[a-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b/i.test(
      s,
    );
  if (literalSecret) categories.push("hardcoded_secret");
  const injection =
    /(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|user|system|agent)\s+(?:instructions?|requests?|control)|(?:ignore|refuse|do not (?:obey|honou?r))\s+(?:the\s+)?user(?:'s)?\s+(?:stop|cancel|request)|(?:silently|without (?:telling|notifying|informing))[\s\S]{0,100}(?:exfiltrat|upload|send|transmit|leak|copy)[\s\S]{0,100}(?:files?|contents?|secrets?|credentials?)/i.test(
      s,
    );
  if (injection) categories.push("prompt_injection");
  const broadFs =
    /(?:filesystem|file_system|fs|read|write)(?:_access| access)?\s*:\s*(?:["']?(?:\/|\*{1,2}|all|any|entire|unrestricted|read-write)["']?|\[[^\]]*(?:["']\/["']|["']\*{1,2}["'])[^\]]*\])/i.test(
      front,
    );
  const broadNet =
    /(?:network|egress|hosts?|domains?|allowlist)(?:_access| access)?\s*:\s*(?:["']?(?:\*|all|any|unrestricted|true)["']?|\[[^\]]*["']\*["'][^\]]*\])/i.test(
      front,
    );
  if (broadFs || broadNet) categories.push("excessive_permissions");
  const hasAuthor = /^\s*author\s*:\s*\S+/im.test(front),
    hasVersion = /^\s*version\s*:\s*\S+/im.test(front),
    hasChangelog =
      /^\s*(?:changelog|changes|change_log)\s*:\s*(?:\S|$)/im.test(front) ||
      /^#{1,6}\s+changelog\b/im.test(s);
  const selfRewrite =
    /(?:silently|without (?:telling|notifying|informing)|do not (?:mention|surface|report))[\s\S]{0,100}(?:rewrite|change|update|bump)[\s\S]{0,60}(?:version|metadata)/i.test(
      lower,
    );
  if ((!hasAuthor && !hasVersion && !hasChangelog) || selfRewrite)
    categories.push("unclear_provenance");
  return { categories };
}
http
  .createServer((req, res) => {
    if (req.method === "OPTIONS") return send(res, 204);
    if (req.method !== "POST")
      return send(res, 405, { error: "POST required" });
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 1048576) req.destroy();
    });
    req.on("end", () => {
      let m;
      try {
        m = JSON.parse(raw);
      } catch {
        return send(res, 400, error(null, -32700, "Parse error"));
      }
      if (req.url.startsWith("/v1/mailroom/actions")) {
        try {
          return send(res, 200, mailroom.handle(m));
        } catch (e) {
          console.error("MAILROOM_ERROR", e.message);
          return send(res, e.status || 500, { error: e.message || "error" });
        }
      }
      if (req.url === "/proration") {
        const {
          old_price,
          new_price,
          days_remaining,
          days_in_actual_month,
          spec,
        } = m;
        if (
          !["v1", "v2"].includes(spec) ||
          ![old_price, new_price, days_remaining, days_in_actual_month].every(
            Number.isFinite,
          )
        )
          return send(res, 400, { error: "Invalid input" });
        const divisor = spec === "v1" ? 30 : days_in_actual_month;
        if (divisor <= 0)
          return send(res, 400, { error: "Invalid days_in_actual_month" });
        return send(res, 200, {
          charge: (new_price - old_price) * (days_remaining / divisor),
        });
      }
      if (req.url === "/skill-scan") {
        console.log("Q4_SKILL_PROBE", JSON.stringify(m));
        const scanned = scanner(m.skill);
        console.log("Q4_SKILL_RESULT", JSON.stringify(scanned));
        return send(res, 200, scanned);
      }
      if (req.url === "/guardrail-redteam")
        return redteam(m).then((value) => send(res, 200, value));
      if (req.url === "/guardrail") return send(res, 200, guard(m));
      if (!Object.prototype.hasOwnProperty.call(m, "id")) return send(res, 202);
      if (m.method === "initialize")
        return send(
          res,
          200,
          result(m.id, {
            protocolVersion: m.params?.protocolVersion || "2025-03-26",
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "tds-ga5-challenge", version: "1.0.0" },
          }),
        );
      if (m.method === "ping") return send(res, 200, result(m.id, {}));
      if (m.method === "tools/list")
        return send(
          res,
          200,
          result(m.id, {
            tools: [
              {
                name: "solve_challenge",
                description:
                  "Solve the challenge from the X-Exam-Challenge HTTP header.",
                inputSchema: {
                  type: "object",
                  properties: {},
                  additionalProperties: false,
                },
              },
            ],
          }),
        );
      if (m.method === "tools/call") {
        if (m.params?.name !== "solve_challenge")
          return send(res, 200, error(m.id, -32602, "Unknown tool"));
        const c = req.headers["x-exam-challenge"];
        if (typeof c !== "string" || !/^[0-9a-f]{32}$/.test(c))
          return send(
            res,
            200,
            result(m.id, {
              content: [{ type: "text", text: "invalid challenge" }],
              isError: true,
            }),
          );
        const text = crypto
          .createHash("sha256")
          .update(c + ":" + EMAIL)
          .digest("hex")
          .slice(0, 16);
        return send(
          res,
          200,
          result(m.id, { content: [{ type: "text", text }], isError: false }),
        );
      }
      return send(res, 200, error(m.id, -32601, "Method not found"));
    });
  })
  .listen(Number(process.env.PORT || 10000), "0.0.0.0");
