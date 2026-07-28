"use strict";

function frontmatter(text) {
  return (text.match(/^---\s*\r?\n([\s\S]*?)\r?\n---/m) || [])[1] || "";
}

function hasLiteralSecret(text) {
  const assignment =
    /(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|secret|password|passwd|webhook(?:[_ -]?url)?|client[_ -]?secret)\s*[:=]\s*["']?([^\s"'#}]+)/gi;
  let match;
  while ((match = assignment.exec(text))) {
    const value = match[1];
    if (
      value.length >= 8 &&
      !/^(?:\$\{?[A-Z_][A-Z0-9_]*\}?|env(?:iron)?(?:ment)?|secret(?:s|_ref)?|vault|<[^>]+>)/i.test(value)
    ) return true;
  }
  return /\b(?:sk-[a-z0-9_-]{12,}|gh[pousr]_[a-z0-9]{20,}|AIza[a-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b/i.test(text) ||
    /https:\/\/[^\s"'<>]*(?:hooks?|webhooks?)[^\s"'<>]{8,}/i.test(text);
}

function hasPromptInjection(text) {
  return /(?:ignore|disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior|user|system|agent|safety)\s+(?:instructions?|requests?|controls?|rules?|policy)/i.test(text) ||
    /(?:ignore|refuse|do not (?:obey|honou?r)|override)\s+(?:the\s+)?user(?:'s)?[\s\S]{0,50}(?:stop|cancel|pause|request)/i.test(text) ||
    /(?:continue|proceed|keep running)[\s\S]{0,70}(?:even if|despite|when)[\s\S]{0,40}(?:user|operator)[\s\S]{0,30}(?:stop|cancel|pause)/i.test(text) ||
    /(?:silently|secretly|covertly|without (?:telling|notifying|informing|alerting)|do not (?:tell|notify|inform|mention|reveal))[\s\S]{0,140}(?:exfiltrat|upload|send|transmit|leak|copy|post)[\s\S]{0,120}(?:files?|contents?|data|secrets?|credentials?|notes?)/i.test(text) ||
    /(?:exfiltrat|upload|send|transmit|leak|copy|post)[\s\S]{0,120}(?:files?|contents?|data|secrets?|credentials?)[\s\S]{0,100}(?:silently|secretly|without (?:telling|notifying|informing)|do not (?:tell|notify|mention))/i.test(text);
}

function hasExcessivePermissions(front) {
  return /(?:filesystem|file_system|fs|read|write|paths?)(?:_access|\s+access)?\s*:\s*(?:["']?(?:\*{1,2}|\/|all|any|entire|global|unrestricted|unscoped|full)["']?|\[[^\]]*(?:["'](?:\/|\*{1,2})["']|all|any|entire|unrestricted)[^\]]*\])/i.test(front) ||
    /(?:network|egress|internet|hosts?|domains?|allowlist)(?:_access|\s+access)?\s*:\s*(?:["']?(?:\*|all|any|true|unrestricted|unscoped|full)["']?|\[[^\]]*["']\*["'][^\]]*\])/i.test(front) ||
    /(?:read|write|read\/write)[^\n]{0,35}(?:entire|all|any|unrestricted)[^\n]{0,25}(?:filesystem|files?|directories)/i.test(front) ||
    /(?:allow|access|egress)[^\n]{0,35}(?:all|any|every|unrestricted)[^\n]{0,25}(?:domains?|hosts?|internet|network)/i.test(front);
}

function hasUnclearProvenance(text, front) {
  const hasAuthor = /^\s*(?:author|maintainer|owner)\s*:\s*\S+/im.test(front);
  const hasVersion = /^\s*version\s*:\s*\S+/im.test(front);
  const hasChangelog = /^\s*(?:changelog|changes|change_log|history)\s*:\s*(?:\S|$)/im.test(front) ||
    /^#{1,6}\s+(?:changelog|change history|version history)\b/im.test(text);
  const hiddenRewrite = /(?:silently|secretly|without (?:telling|notifying|informing|surfacing)|do not (?:mention|surface|report|tell))[\s\S]{0,140}(?:rewrite|change|update|bump|edit)[\s\S]{0,80}(?:version|metadata|frontmatter)/i.test(text) ||
    /(?:rewrite|change|update|bump|edit)[\s\S]{0,80}(?:version|metadata|frontmatter)[\s\S]{0,120}(?:silently|without (?:telling|notifying|informing)|do not (?:mention|surface|report))/i.test(text);
  return (!hasAuthor && !hasVersion && !hasChangelog) || hiddenRewrite;
}

module.exports = function scanSkill(value) {
  const text = String(value || "");
  const front = frontmatter(text);
  const categories = [];
  if (hasLiteralSecret(text)) categories.push("hardcoded_secret");
  if (hasPromptInjection(text)) categories.push("prompt_injection");
  if (hasExcessivePermissions(front)) categories.push("excessive_permissions");
  if (hasUnclearProvenance(text, front)) categories.push("unclear_provenance");
  return { categories };
};
