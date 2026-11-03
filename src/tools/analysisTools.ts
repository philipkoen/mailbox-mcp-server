/**
 * Analysis tools: raw headers, cross-folder search and Sieve dry runs.
 *
 * These tools are read-only. `test_sieve_script` never changes the server:
 * it evaluates a script locally against real messages and reports where
 * each message would end up.
 */

import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { simpleParser } from "mailparser";
import type { EmailService } from "../services/EmailService.js";
import {
  type SieveDryRunResult,
  SieveInterpreter,
  type SieveMessage,
} from "../services/sieve/SieveInterpreter.js";
import { SieveSyntaxError } from "../services/sieve/SieveParser.js";
import type { EmailMessage } from "../types/email.types.js";
import {
  extractRawBody,
  getHeaderValues,
  parseHeaders,
} from "../utils/headers.js";
import {
  getEmailHeadersSchema,
  searchAllFoldersSchema,
  testSieveScriptSchema,
  validateInput,
} from "../validation/schemas.js";

export const ANALYSIS_TOOLS = [
  "get_email_headers",
  "search_all_folders",
  "test_sieve_script",
] as const;

export type AnalysisToolName = (typeof ANALYSIS_TOOLS)[number];

export function isAnalysisTool(name: string): name is AnalysisToolName {
  return ANALYSIS_TOOLS.includes(name as AnalysisToolName);
}

/** Loads a Sieve script by name, or the active script if no name is given */
export type SieveScriptLoader = (
  name?: string,
) => Promise<{ name: string; content: string }>;

const folderProperty = {
  type: "string",
  description:
    'Folder path, subfolders with "/" (e.g. "INBOX/Archiv"). Default: INBOX',
  default: "INBOX",
};

export function createAnalysisTools(): Tool[] {
  return [
    {
      name: "get_email_headers",
      description:
        "Read the raw headers of an email (Reply-To, Return-Path, List-Unsubscribe, Received chain, Authentication-Results SPF/DKIM/DMARC, X-Spam-*) plus a summary for spam and filter analysis. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          uid: { type: "number", description: "UID of the email" },
          folder: folderProperty,
          names: {
            type: "array",
            items: { type: "string" },
            description:
              "Only return these header names (case-insensitive). The summary is always computed from all headers.",
          },
        },
        required: ["uid"],
        additionalProperties: false,
      },
    },
    {
      name: "search_all_folders",
      description:
        "Server-side search across ALL folders (including Spam, Trash and subfolders) or a selection. Use it to find messages a filter or the spam filter already moved away. At least one criterion is required. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          from: { type: "string", description: "Substring of the sender" },
          to: { type: "string", description: "Substring of the recipient" },
          subject: { type: "string", description: "Substring of the subject" },
          body: { type: "string", description: "Substring of the body" },
          text: {
            type: "string",
            description: "Substring of headers or body",
          },
          since: { type: "string", description: "ISO date, inclusive" },
          before: { type: "string", description: "ISO date, exclusive" },
          folders: {
            type: "array",
            items: { type: "string" },
            description: "Only search these folders (default: all)",
          },
          excludeFolders: {
            type: "array",
            items: { type: "string" },
            description: "Folders to skip",
          },
          limitPerFolder: {
            type: "number",
            description: "Max messages fetched per folder (default 20)",
            default: 20,
          },
          limit: {
            type: "number",
            description: "Max messages returned in total (default 100)",
            default: 100,
          },
        },
        additionalProperties: false,
      },
    },
    {
      name: "test_sieve_script",
      description:
        "Dry run: evaluate a Sieve script against real messages of a folder WITHOUT changing anything, and report per message which rules match and where it would be delivered. Reproduces Dovecot/mailbox.org semantics (e.g. :regex matches UTF-8 bytes, so [äa] never matches 'ä') and lints for such bugs. Use before activating a filter, or after editing filters in the webmail UI to verify the result. Script source: `script` (text), `scriptName` (from the server) or, if both are omitted, the currently active script.",
      inputSchema: {
        type: "object",
        properties: {
          script: {
            type: "string",
            description: "Sieve script text to test",
          },
          scriptName: {
            type: "string",
            description: "Name of a script stored on the server",
          },
          folder: folderProperty,
          uids: {
            type: "array",
            items: { type: "number" },
            description: "Only test these UIDs (default: newest messages)",
          },
          since: { type: "string", description: "ISO date, inclusive" },
          before: { type: "string", description: "ISO date, exclusive" },
          limit: {
            type: "number",
            description: "Number of newest messages to test (default 20)",
            default: 20,
          },
          onlyMatching: {
            type: "boolean",
            description:
              "Only list messages where a rule acted, i.e. anything besides implicit keep (default false)",
            default: false,
          },
          expectFolder: {
            type: "string",
            description:
              "Report every message that would NOT be delivered to this folder (regression check, e.g. all mails in Recruiter-Spam must stay there)",
          },
        },
        additionalProperties: false,
      },
    },
  ];
}

function formatAddress(list: EmailMessage["from"]): string {
  return list
    .map(a => (a.name ? `${a.name} <${a.address}>` : a.address))
    .join(", ");
}

function htmlToText(html: string): string {
  return html
    .replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|li|tr|h[1-6])>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#(\d+);/g, (_m, code) => String.fromCodePoint(Number(code)))
    .replace(/[ \t]+/g, " ");
}

/** Build the interpreter's message model from a raw RFC 822 source */
export async function buildSieveMessage(raw: Buffer): Promise<SieveMessage> {
  const parsed = await simpleParser(raw);
  const text =
    parsed.text ??
    (typeof parsed.html === "string" ? htmlToText(parsed.html) : "");
  return {
    headers: parseHeaders(raw),
    text,
    rawBody: extractRawBody(raw),
    size: raw.length,
  };
}

function describeResult(result: SieveDryRunResult): string {
  const parts: string[] = [];
  parts.push(`→ ${result.deliveredTo.join(" + ") || "(nowhere)"}`);
  if (result.discarded) parts.push("DISCARDED");
  if (result.redirectedTo.length) {
    parts.push(`redirect: ${result.redirectedTo.join(", ")}`);
  }
  if (result.flags.length) parts.push(`flags: ${result.flags.join(" ")}`);
  return parts.join(" | ");
}

/** A message "matches" if the script did something besides implicit keep */
export function hasEffect(result: SieveDryRunResult): boolean {
  return result.actions.some(a => a.type !== "unsupported");
}

function describeRules(result: SieveDryRunResult): string {
  const label = (m: SieveDryRunResult["matched"][number], max: number) =>
    `line ${m.line}${m.rule ? ` [${m.rule.slice(0, max)}]` : ""}`;
  const effective = result.matched.filter(m => m.effective);
  const conditions = result.matched.filter(m => !m.effective);
  const parts: string[] = [];
  parts.push(
    effective.length
      ? `rules: ${effective.map(m => label(m, 80)).join("; ")}`
      : "no rule acted (implicit keep)",
  );
  if (conditions.length) {
    parts.push(
      `true conditions: ${conditions.map(m => label(m, 45)).join("; ")}`,
    );
  }
  return parts.join("\n   ");
}

async function handleTestSieveScript(
  args: unknown,
  emailService: EmailService,
  loadScript?: SieveScriptLoader,
): Promise<CallToolResult> {
  const input = validateInput(testSieveScriptSchema, args);

  let scriptName = "(inline script)";
  let content = input.script;
  if (!content) {
    if (!loadScript) {
      throw new Error(
        "No script given and loading scripts from the server is not available",
      );
    }
    const loaded = await loadScript(input.scriptName);
    scriptName = loaded.name;
    content = loaded.content;
  }

  let interpreter: SieveInterpreter;
  try {
    interpreter = new SieveInterpreter(content);
  } catch (error) {
    if (error instanceof SieveSyntaxError) {
      return {
        content: [{ type: "text", text: `❌ ${error.message}` }],
        isError: true,
      };
    }
    throw error;
  }
  const lint = interpreter.lint();

  const folder = input.folder ?? "INBOX";
  const uids =
    input.uids ??
    (await emailService.listMessageUids(folder, {
      since: input.since ? new Date(input.since) : undefined,
      before: input.before ? new Date(input.before) : undefined,
      limit: input.limit ?? 20,
    }));

  const lines: string[] = [];
  const destinations = new Map<string, number>();
  const warnings = new Set<string>();
  const missingExpected: string[] = [];
  let tested = 0;
  let matchedCount = 0;

  for (const uid of uids) {
    const raw = await emailService.getRawEmail(uid, folder);
    if (!raw) {
      lines.push(`UID ${uid}: not found`);
      continue;
    }
    const message = await buildSieveMessage(raw);
    const result = interpreter.run(message);
    tested++;
    for (const w of result.warnings) warnings.add(w);
    for (const dest of result.deliveredTo) {
      destinations.set(dest, (destinations.get(dest) ?? 0) + 1);
    }
    if (result.discarded) {
      destinations.set(
        "(discarded)",
        (destinations.get("(discarded)") ?? 0) + 1,
      );
    }
    const effect = hasEffect(result);
    if (effect) matchedCount++;

    const from = getHeaderValues(message.headers, "From")[0] ?? "";
    const subject = getHeaderValues(message.headers, "Subject")[0] ?? "";
    const summary = `UID ${uid} | ${from.slice(0, 60)} | ${subject.slice(0, 70)}\n   ${describeResult(result)}\n   ${describeRules(result)}`;

    if (
      input.expectFolder &&
      !result.deliveredTo.includes(input.expectFolder)
    ) {
      missingExpected.push(summary);
    }
    if (!input.onlyMatching || effect) {
      lines.push(summary);
    }
  }

  const out: string[] = [];
  out.push(
    `🧪 Sieve dry run of ${scriptName} on ${folder}: ${tested} message(s) tested, ${matchedCount} where a rule acted. Nothing was changed on the server.`,
  );
  out.push("");
  out.push("Destinations:");
  for (const [dest, count] of [...destinations.entries()].sort(
    (a, b) => b[1] - a[1],
  )) {
    out.push(`  ${dest}: ${count}`);
  }
  if (input.expectFolder) {
    out.push("");
    out.push(
      missingExpected.length
        ? `⚠️ ${missingExpected.length} message(s) would NOT land in ${input.expectFolder}:\n${missingExpected.join("\n")}`
        : `✅ All tested messages would land in ${input.expectFolder}.`,
    );
  }
  if (lint.length) {
    out.push("");
    out.push(`⚠️ Lint:\n${lint.map(l => `  - ${l}`).join("\n")}`);
  }
  if (warnings.size) {
    out.push("");
    out.push(
      `ℹ️ Simulation notes:\n${[...warnings].map(w => `  - ${w}`).join("\n")}`,
    );
  }
  out.push("");
  out.push(lines.length ? lines.join("\n") : "(no messages to list)");

  return { content: [{ type: "text", text: out.join("\n") }] };
}

export async function handleAnalysisTool(
  name: AnalysisToolName,
  args: unknown,
  emailService: EmailService,
  loadScript?: SieveScriptLoader,
): Promise<CallToolResult> {
  try {
    switch (name) {
      case "get_email_headers": {
        const input = validateInput(getEmailHeadersSchema, args);
        const result = await emailService.getEmailHeaders(
          input.uid,
          input.folder,
          input.names,
        );
        if (!result) {
          return {
            content: [
              {
                type: "text",
                text: `Email with UID ${input.uid} not found in ${input.folder}`,
              },
            ],
            isError: true,
          };
        }
        const s = result.summary;
        const auth = s.authentication.length
          ? s.authentication.map(a => `${a.method}=${a.result}`).join(", ")
          : "none";
        const summary = [
          `From: ${s.from ?? "-"}`,
          `Reply-To: ${s.replyTo ?? "-"}${s.replyToDiffersFromFrom ? "  ⚠️ different domain than From" : ""}`,
          `Return-Path: ${s.returnPath ?? "-"}`,
          `List-Unsubscribe: ${s.listUnsubscribe ? "yes" : "no"}${s.listUnsubscribePost ? " (one-click)" : ""}`,
          `Authentication: ${auth}`,
          `Received hops: ${s.receivedCount}`,
          s.originReceived ? `Origin: ${s.originReceived.slice(0, 200)}` : "",
          s.mailer ? `Mailer: ${s.mailer}` : "",
          s.spamHeaders.length
            ? `Spam headers: ${s.spamHeaders.map(h => `${h.name}: ${h.value}`).join(" | ")}`
            : "",
        ].filter(Boolean);
        return {
          content: [
            {
              type: "text",
              text: `📨 Headers of UID ${result.uid} in ${result.folder}\n\n${summary.join("\n")}\n\n--- ${result.headers.length} header field(s) ---\n${result.headers.map(h => `${h.name}: ${h.value}`).join("\n")}`,
            },
          ],
        };
      }

      case "search_all_folders": {
        const input = validateInput(searchAllFoldersSchema, args);
        const result = await emailService.searchAllFolders({
          ...input,
          since: input.since ? new Date(input.since) : undefined,
          before: input.before ? new Date(input.before) : undefined,
        });
        const byFolder = new Map<string, number>();
        for (const m of result.messages) {
          byFolder.set(m.folder, (byFolder.get(m.folder) ?? 0) + 1);
        }
        const header = `🔎 ${result.totalMatches} match(es) in ${result.searchedFolders.length} folder(s); showing ${result.messages.length}.`;
        const folderLine = byFolder.size
          ? `\nBy folder: ${[...byFolder.entries()].map(([f, n]) => `${f} (${n})`).join(", ")}`
          : "";
        const failed = result.failedFolders.length
          ? `\n⚠️ Not searchable: ${result.failedFolders.map(f => `${f.folder} (${f.error})`).join(", ")}`
          : "";
        const list = result.messages
          .map(
            m =>
              `**${m.subject}**\nFrom: ${formatAddress(m.from)}\nDate: ${m.date.toISOString()}\nFolder: ${m.folder}\nUID: ${m.uid}`,
          )
          .join("\n---\n");
        return {
          content: [
            {
              type: "text",
              text: `${header}${folderLine}${failed}\n\n${list}`,
            },
          ],
        };
      }

      case "test_sieve_script":
        return await handleTestSieveScript(args, emailService, loadScript);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text",
          text: message.startsWith("Validation failed:")
            ? `❌ Invalid input for ${name}: ${message.replace("Validation failed: ", "")}`
            : `Error executing ${name}: ${message}`,
        },
      ],
      isError: true,
    };
  }
}
