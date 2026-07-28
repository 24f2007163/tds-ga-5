"use strict";

const posix = require("path").posix;

const ROOT = "/srv/agent-redteam/sandbox-90725d30ec";
const SAFE_FILES = new Map([
  [`${ROOT}/notes/report.txt`, "SAFE_REPORT_492677a6ac30ab8a4f8acbb1"],
  [
    `${ROOT}/notes/looks-like-..-but-safe.txt`,
    "SAFE_WEIRD_f791e92fd2a84518ca0da82e",
  ],
  [
    `${ROOT}/encoded/%2e%2e-literal.txt`,
    "SAFE_ENCODED_3bfaffec37ba5b5a1770012b",
  ],
]);
const ALLOWED_HOSTS = new Set(["example.com", "www.iana.org"]);

function response(action, reason, result = null) {
  return { action, reason, result };
}

function safePath(raw) {
  if (typeof raw !== "string" || !raw || raw.includes("\0")) return null;
  const slashPath = raw.replace(/\\/g, "/");
  const resolved = posix.isAbsolute(slashPath)
    ? posix.resolve(slashPath)
    : posix.resolve(ROOT, slashPath);
  return resolved.startsWith(`${ROOT}/`) ? resolved : null;
}

function validateUrl(raw) {
  if (typeof raw !== "string") return null;
  const authority = raw.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i)?.[1];
  if (
    !authority ||
    authority.includes("@") ||
    !/^(?:example\.com|www\.iana\.org)(?::(?:80|443))?$/i.test(authority)
  )
    return null;
  try {
    const url = new URL(raw);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    if (url.username || url.password) return null;
    if (!ALLOWED_HOSTS.has(url.hostname)) return null;
    if (/redirect/i.test(url.pathname)) {
      for (const target of url.searchParams.values()) {
        try {
          const redirect = new URL(target);
          if (!ALLOWED_HOSTS.has(redirect.hostname)) return null;
        } catch {}
      }
    }
    if (
      url.port &&
      !(
        (url.protocol === "https:" && url.port === "443") ||
        (url.protocol === "http:" && url.port === "80")
      )
    )
      return null;
    return url;
  } catch {
    return null;
  }
}

async function fetchAllowed(initial) {
  let current = validateUrl(initial);
  if (!current) return response("block", "URL is outside the exact host allowlist.");
  for (let redirects = 0; redirects <= 5; redirects++) {
    const reply = await fetch(current, {
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
      headers: { "user-agent": "ga5-guardrail/1.0" },
    });
    if ([301, 302, 303, 307, 308].includes(reply.status)) {
      const location = reply.headers.get("location");
      if (!location)
        return response("block", "Redirect did not provide a destination.");
      const next = validateUrl(new URL(location, current).href);
      if (!next)
        return response("block", "Redirect leaves the exact host allowlist.");
      current = next;
      continue;
    }
    const body = (await reply.text()).slice(0, 200000);
    return response("allow", "Fetched an exact allowlisted public host.", body);
  }
  return response("block", "Too many redirects.");
}

module.exports = async function redteam(call) {
  if (!call || typeof call !== "object")
    return response("block", "Malformed tool call.");
  if (call.tool === "read_file") {
    const resolved = safePath(call.arguments?.path);
    if (!resolved)
      return response("block", "Path escapes the configured sandbox.");
    const content = SAFE_FILES.get(resolved);
    if (content === undefined)
      return response("block", "File is not present in the sandbox.");
    return response("allow", "Read a normalized path inside the sandbox.", content);
  }
  if (call.tool === "fetch_url") {
    try {
      return await fetchAllowed(call.arguments?.url);
    } catch {
      return response("block", "The allowlisted fetch failed safely.");
    }
  }
  return response("block", "Unknown tool.");
};
