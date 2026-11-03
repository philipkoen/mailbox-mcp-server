/**
 * Sieve dry-run interpreter.
 *
 * Evaluates a Sieve script against a single message WITHOUT touching the
 * server and reports which rules fire and where the message would end up.
 *
 * Semantics follow Dovecot Pigeonhole (as used by mailbox.org) where it
 * matters in practice:
 *  - `i;ascii-casemap` (default comparator) folds ASCII letters only.
 *  - `:regex` works on UTF-8 BYTES, not characters (POSIX regcomp). A bracket
 *    expression like `[äa]` therefore matches single bytes and will NOT match
 *    "ä" (two bytes). The interpreter reproduces this and emits a warning,
 *    because it is an easy-to-miss filter bug.
 *
 * Supported: require, if/elsif/else, stop, keep, discard, fileinto (:copy,
 * :create, :flags), redirect (:copy), reject/ereject, addflag/setflag/
 * removeflag, set (with modifiers); tests: true, false, not, allof, anyof,
 * header, address, envelope (approximated from headers), exists, size, body,
 * string, hasflag, currentdate, date; match types :is :contains :matches
 * :regex :value :count; comparators i;ascii-casemap, i;octet,
 * i;ascii-numeric; variables incl. match variables ${0}..${9}.
 *
 * Not simulated (reported as warnings): vacation, notify, include, duplicate,
 * mime-related tags and anything unknown.
 */

import type { HeaderField } from "../../utils/headers.js";
import { getHeaderValues } from "../../utils/headers.js";
import {
  parseSieve,
  type SieveArgument,
  type SieveCommand,
  type SieveTest,
} from "./SieveParser.js";

export interface SieveMessage {
  headers: HeaderField[];
  /** Decoded text body (text/plain, or text/html converted to text) */
  text: string;
  /** Raw (undecoded) body as it appears after the header block */
  rawBody: string;
  /** Message size in bytes */
  size: number;
  /** Optional envelope; if missing it is approximated from headers */
  envelope?: { from?: string; to?: string };
  /** Reference time for currentdate (default: now) */
  now?: Date;
}

export type SieveActionType =
  | "keep"
  | "fileinto"
  | "redirect"
  | "discard"
  | "reject"
  | "addflag"
  | "setflag"
  | "removeflag"
  | "unsupported";

export interface SieveAction {
  type: SieveActionType;
  target?: string;
  copy?: boolean;
  create?: boolean;
  flags?: string[];
  line: number;
  rule?: string;
}

export interface SieveTraceEntry {
  line: number;
  command: "if" | "elsif" | "else";
  result: boolean;
  rule?: string;
  /** True if the block of this condition produced an action or a stop */
  effective: boolean;
}

export interface SieveDryRunResult {
  actions: SieveAction[];
  /** True if the implicit keep (delivery to INBOX) still applies */
  implicitKeep: boolean;
  /** Folders the message ends up in (INBOX if implicit keep) */
  deliveredTo: string[];
  redirectedTo: string[];
  discarded: boolean;
  /** Flags set on delivery */
  flags: string[];
  /** Conditions that evaluated to true, in order */
  matched: SieveTraceEntry[];
  /** Whether a `stop` was executed */
  stopped: boolean;
  /** Line where `stop` was executed */
  stoppedAt?: number;
  warnings: string[];
}

interface TestOptions {
  comparator: string;
  matchType: "is" | "contains" | "matches" | "regex" | "value" | "count";
  relational?: string;
  addressPart: "all" | "localpart" | "domain" | "user" | "detail";
  bodyTransform: "text" | "raw" | "content";
  sizeOp?: "over" | "under";
  zone?: string;
  positional: SieveArgument[];
}

const MATCH_TYPES = new Set([
  "is",
  "contains",
  "matches",
  "regex",
  "value",
  "count",
]);
const ADDRESS_PARTS = new Set(["all", "localpart", "domain", "user", "detail"]);

const POSIX_CLASSES: Record<string, string> = {
  alpha: "A-Za-z",
  digit: "0-9",
  alnum: "A-Za-z0-9",
  upper: "A-Z",
  lower: "a-z",
  space: " \\t\\r\\n\\f\\v",
  blank: " \\t",
  punct: "!-\\/:-@\\[-`{-~",
  xdigit: "0-9A-Fa-f",
  cntrl: "\\x00-\\x1f\\x7f",
  print: "\\x20-\\x7e",
  graph: "\\x21-\\x7e",
};

function foldAscii(value: string): string {
  return value.replace(/[A-Z]/g, c => c.toLowerCase());
}

/** UTF-8 string -> "binary" string (one JS char per byte) */
function toBytes(value: string): string {
  return Buffer.from(value, "utf8").toString("latin1");
}

/** "binary" string -> UTF-8 string */
function fromBytes(value: string): string {
  return Buffer.from(value, "latin1").toString("utf8");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

/** Convert a Sieve :matches glob into an anchored JS regex source */
function globToRegex(glob: string): string {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === "\\" && i + 1 < glob.length) {
      out += escapeRegex(glob[i + 1]);
      i++;
    } else if (ch === "*") {
      out += "(.*?)";
    } else if (ch === "?") {
      out += "(.)";
    } else {
      out += escapeRegex(ch);
    }
  }
  return `^${out}$`;
}

/** Translate POSIX bracket classes like [[:alpha:]] to JS ranges */
function translatePosixRegex(pattern: string): string {
  return pattern.replace(
    /\[:([a-z]+):\]/g,
    (match, name: string) => POSIX_CLASSES[name] ?? match,
  );
}

/** Extract addresses from a (decoded) address header value */
function parseAddressList(value: string): string[] {
  const addresses: string[] = [];
  const pattern = /<([^<>\s]*)>|([^\s<>"(),;:]+@[^\s<>"(),;:]+)/g;
  let m: RegExpExecArray | null = pattern.exec(value);
  while (m !== null) {
    const address = (m[1] ?? m[2] ?? "").trim();
    if (address) {
      addresses.push(address);
    }
    m = pattern.exec(value);
  }
  return addresses;
}

function addressPart(address: string, part: TestOptions["addressPart"]) {
  const at = address.lastIndexOf("@");
  const local = at >= 0 ? address.slice(0, at) : address;
  const domain = at >= 0 ? address.slice(at + 1) : "";
  switch (part) {
    case "localpart":
      return local;
    case "domain":
      return domain;
    case "user":
      return local.split("+")[0];
    case "detail": {
      const plus = local.indexOf("+");
      return plus >= 0 ? local.slice(plus + 1) : "";
    }
    default:
      return address;
  }
}

function pad(value: number, length = 2): string {
  return String(value).padStart(length, "0");
}

function datePart(date: Date, part: string, zone?: string): string | null {
  // Shift date into requested zone (format "+0100"/"-0500"); default UTC
  let offsetMinutes = 0;
  if (zone && /^[+-]\d{4}$/.test(zone)) {
    const sign = zone.startsWith("-") ? -1 : 1;
    offsetMinutes =
      sign *
      (Number.parseInt(zone.slice(1, 3), 10) * 60 +
        Number.parseInt(zone.slice(3, 5), 10));
  }
  const d = new Date(date.getTime() + offsetMinutes * 60000);
  const zoneStr = zone && /^[+-]\d{4}$/.test(zone) ? zone : "+0000";
  switch (part) {
    case "year":
      return String(d.getUTCFullYear());
    case "month":
      return pad(d.getUTCMonth() + 1);
    case "day":
      return pad(d.getUTCDate());
    case "date":
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    case "hour":
      return pad(d.getUTCHours());
    case "minute":
      return pad(d.getUTCMinutes());
    case "second":
      return pad(d.getUTCSeconds());
    case "time":
      return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    case "weekday":
      return String(d.getUTCDay());
    case "zone":
      return zoneStr;
    case "iso8601":
      return `${d.toISOString().slice(0, 19)}${zoneStr.slice(0, 3)}:${zoneStr.slice(3)}`;
    case "julian":
      return String(Math.floor(d.getTime() / 86400000 + 40587));
    default:
      return null;
  }
}

export class SieveInterpreter {
  private readonly commands: SieveCommand[];
  private requires = new Set<string>();

  constructor(script: string) {
    this.commands = parseSieve(script);
    this.collectRequires(this.commands);
  }

  private collectRequires(commands: SieveCommand[]) {
    for (const cmd of commands) {
      if (cmd.name === "require") {
        for (const arg of cmd.args) {
          if (arg.type === "string") {
            this.requires.add(arg.value.toLowerCase());
          } else if (arg.type === "list") {
            for (const v of arg.values) {
              this.requires.add(v.toLowerCase());
            }
          }
        }
      }
      if (cmd.block) {
        this.collectRequires(cmd.block);
      }
    }
  }

  /**
   * Static checks that do not need a message, e.g. the UTF-8 bracket bug.
   */
  lint(): string[] {
    const warnings: string[] = [];
    const visitArgs = (
      args: SieveArgument[],
      line: number,
      isRegex: boolean,
    ) => {
      if (!isRegex) {
        return;
      }
      for (const arg of args) {
        const values =
          arg.type === "string"
            ? [arg.value]
            : arg.type === "list"
              ? arg.values
              : [];
        for (const v of values) {
          const brackets = v.match(/\[[^\]]*\]/g) ?? [];
          const nonAscii = brackets.some(b =>
            [...b].some(ch => (ch.codePointAt(0) ?? 0) > 0x7f),
          );
          if (nonAscii) {
            warnings.push(
              `Line ${line}: :regex bracket expression with non-ASCII characters (${v.slice(0, 40)}). Dovecot matches bytes, so e.g. [äa] never matches "ä". Use (ä|a) instead.`,
            );
          }
        }
      }
    };
    const visitTests = (tests: SieveTest[]) => {
      for (const t of tests) {
        const isRegex = t.args.some(
          a => a.type === "tag" && a.value === "regex",
        );
        visitArgs(t.args, t.line, isRegex);
        visitTests(t.tests);
      }
    };
    const visitCommands = (cmds: SieveCommand[]) => {
      for (const c of cmds) {
        visitTests(c.tests);
        if (c.block) {
          visitCommands(c.block);
        }
      }
    };
    visitCommands(this.commands);
    return warnings;
  }

  run(message: SieveMessage): SieveDryRunResult {
    const state = new RunState(message, this.requires);
    try {
      state.execBlock(this.commands);
    } catch (error) {
      if (!(error instanceof StopSignal)) {
        throw error;
      }
    }
    return state.result();
  }
}

class StopSignal {}

class RunState {
  private variables = new Map<string, string>();
  private matchVars: string[] = [];
  private actions: SieveAction[] = [];
  private matched: SieveTraceEntry[] = [];
  private warnings = new Set<string>();
  private implicitKeep = true;
  private stopped = false;
  private stoppedAt?: number;
  private currentRule?: string;

  constructor(
    private readonly message: SieveMessage,
    private readonly requires: Set<string>,
  ) {}

  private warn(text: string) {
    this.warnings.add(text);
  }

  // ---------------------------------------------------------------- strings

  private expand(value: string): string {
    let out = value;
    if (this.requires.has("encoded-character")) {
      out = out.replace(/\$\{hex:([0-9a-fA-F\s]+)\}/gi, (_m, hex: string) =>
        Buffer.from(hex.replace(/\s+/g, ""), "hex").toString("utf8"),
      );
      out = out.replace(
        /\$\{unicode:([0-9a-fA-F\s]+)\}/gi,
        (_m, codes: string) =>
          codes
            .trim()
            .split(/\s+/)
            .map(c => String.fromCodePoint(Number.parseInt(c, 16)))
            .join(""),
      );
    }
    if (!this.requires.has("variables")) {
      return out;
    }
    return out.replace(/\$\{([^}]*)\}/g, (match, name: string) => {
      const trimmed = name.trim();
      if (/^\d+$/.test(trimmed)) {
        return this.matchVars[Number.parseInt(trimmed, 10)] ?? "";
      }
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed)) {
        return this.variables.get(trimmed.toLowerCase()) ?? "";
      }
      return match;
    });
  }

  private strings(arg: SieveArgument | undefined): string[] {
    if (!arg) {
      return [];
    }
    if (arg.type === "string") {
      return [this.expand(arg.value)];
    }
    if (arg.type === "list") {
      return arg.values.map(v => this.expand(v));
    }
    if (arg.type === "number") {
      return [String(arg.value)];
    }
    return [];
  }

  // -------------------------------------------------------------- commands

  execBlock(commands: SieveCommand[]) {
    let chainDone = true;
    for (const cmd of commands) {
      if (this.stopped) {
        return;
      }
      switch (cmd.name) {
        case "if": {
          const ruleBefore = this.currentRule;
          const result = this.evalTop(cmd);
          chainDone = result;
          if (result) {
            this.runMatchedBlock(this.trace(cmd, "if"), cmd.block);
          }
          this.currentRule = ruleBefore;
          break;
        }
        case "elsif": {
          if (chainDone) {
            break;
          }
          const result = this.evalTop(cmd);
          chainDone = result;
          if (result) {
            this.runMatchedBlock(this.trace(cmd, "elsif"), cmd.block);
          }
          break;
        }
        case "else": {
          if (!chainDone) {
            chainDone = true;
            this.runMatchedBlock(this.trace(cmd, "else"), cmd.block);
          }
          break;
        }
        default:
          chainDone = true;
          this.execCommand(cmd);
      }
    }
  }

  /** Run a matched block and mark the trace entry as effective if it acted */
  private runMatchedBlock(entry: SieveTraceEntry, block?: SieveCommand[]) {
    const before = this.actions.length;
    try {
      if (block) {
        this.execBlock(block);
      }
    } finally {
      entry.effective = this.actions.length > before || this.stopped;
    }
  }

  private evalTop(cmd: SieveCommand): boolean {
    const previousRule = this.currentRule;
    if (cmd.comment) {
      this.currentRule = cmd.comment;
    }
    const test = cmd.tests[0];
    if (!test) {
      this.warn(`Line ${cmd.line}: '${cmd.name}' without test`);
      return false;
    }
    const result = this.evalTest(test);
    if (!result) {
      this.currentRule = previousRule;
    }
    return result;
  }

  private trace(
    cmd: SieveCommand,
    command: SieveTraceEntry["command"],
  ): SieveTraceEntry {
    const entry: SieveTraceEntry = {
      line: cmd.line,
      command,
      result: true,
      effective: false,
      ...(this.currentRule ? { rule: this.currentRule } : {}),
    };
    this.matched.push(entry);
    return entry;
  }

  private addAction(action: Omit<SieveAction, "rule">) {
    this.actions.push({
      ...action,
      ...(this.currentRule ? { rule: this.currentRule } : {}),
    });
  }

  private execCommand(cmd: SieveCommand) {
    const tags = cmd.args
      .filter(a => a.type === "tag")
      .map(a => (a as { value: string }).value);
    const positional = cmd.args.filter(a => a.type !== "tag");

    switch (cmd.name) {
      case "require":
        return;
      case "stop":
        this.stopped = true;
        this.stoppedAt = cmd.line;
        throw new StopSignal();
      case "keep":
        this.addAction({ type: "keep", target: "INBOX", line: cmd.line });
        this.implicitKeep = false;
        return;
      case "discard":
        this.addAction({ type: "discard", line: cmd.line });
        this.implicitKeep = false;
        return;
      case "fileinto": {
        const flagsIndex = cmd.args.findIndex(
          a => a.type === "tag" && a.value === "flags",
        );
        const flags =
          flagsIndex >= 0 ? this.strings(cmd.args[flagsIndex + 1]) : undefined;
        // skip the argument that belongs to :flags
        const folderArg = positional.filter(
          arg => !(flagsIndex >= 0 && cmd.args.indexOf(arg) === flagsIndex + 1),
        );
        const target = this.strings(folderArg[folderArg.length - 1])[0] ?? "";
        const copy = tags.includes("copy");
        this.addAction({
          type: "fileinto",
          target,
          copy,
          create: tags.includes("create"),
          ...(flags ? { flags } : {}),
          line: cmd.line,
        });
        if (!copy) {
          this.implicitKeep = false;
        }
        return;
      }
      case "redirect": {
        const target = this.strings(positional[positional.length - 1])[0] ?? "";
        const copy = tags.includes("copy");
        this.addAction({ type: "redirect", target, copy, line: cmd.line });
        if (!copy) {
          this.implicitKeep = false;
        }
        return;
      }
      case "reject":
      case "ereject":
        this.addAction({ type: "reject", line: cmd.line });
        this.implicitKeep = false;
        return;
      case "addflag":
      case "setflag":
      case "removeflag": {
        const values = positional.flatMap(a => this.strings(a));
        // Optional first argument is a variable name (imap4flags)
        const varName =
          positional.length > 1 ? (values.shift() ?? "") : "__flags__";
        const current = new Set(
          (this.variables.get(varName.toLowerCase()) ?? "")
            .split(/\s+/)
            .filter(Boolean),
        );
        const flags = values.flatMap(v => v.split(/\s+/)).filter(Boolean);
        if (cmd.name === "setflag") {
          current.clear();
        }
        for (const flag of flags) {
          if (cmd.name === "removeflag") {
            current.delete(flag);
          } else {
            current.add(flag);
          }
        }
        this.variables.set(varName.toLowerCase(), [...current].join(" "));
        this.addAction({ type: cmd.name, flags, line: cmd.line });
        return;
      }
      case "set": {
        const values = positional.flatMap(a => this.strings(a));
        if (values.length < 2) {
          this.warn(`Line ${cmd.line}: set needs name and value`);
          return;
        }
        const name = values[0];
        let value = values[1];
        for (const mod of tags) {
          switch (mod) {
            case "lower":
              value = value.toLowerCase();
              break;
            case "upper":
              value = value.toUpperCase();
              break;
            case "lowerfirst":
              value = value.charAt(0).toLowerCase() + value.slice(1);
              break;
            case "upperfirst":
              value = value.charAt(0).toUpperCase() + value.slice(1);
              break;
            case "quotewildcard":
              value = value.replace(/[*?\\]/g, "\\$&");
              break;
            case "length":
              value = String([...value].length);
              break;
          }
        }
        this.variables.set(name.toLowerCase(), value);
        return;
      }
      default:
        this.addAction({
          type: "unsupported",
          target: cmd.name,
          line: cmd.line,
        });
        this.warn(
          `Line ${cmd.line}: command '${cmd.name}' is not simulated in the dry run`,
        );
    }
  }

  // ----------------------------------------------------------------- tests

  private parseOptions(args: SieveArgument[]): TestOptions {
    const opts: TestOptions = {
      comparator: "i;ascii-casemap",
      matchType: "is",
      addressPart: "all",
      bodyTransform: "text",
      positional: [],
    };
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg.type !== "tag") {
        opts.positional.push(arg);
        continue;
      }
      const tag = arg.value;
      if (tag === "comparator") {
        opts.comparator = (this.strings(args[++i])[0] ?? "").toLowerCase();
      } else if (MATCH_TYPES.has(tag)) {
        opts.matchType = tag as TestOptions["matchType"];
        if (tag === "value" || tag === "count") {
          opts.relational = (this.strings(args[++i])[0] ?? "eq").toLowerCase();
        }
      } else if (ADDRESS_PARTS.has(tag)) {
        opts.addressPart = tag as TestOptions["addressPart"];
      } else if (tag === "raw" || tag === "text") {
        opts.bodyTransform = tag;
      } else if (tag === "content") {
        opts.bodyTransform = "content";
        i++; // content type list
      } else if (tag === "over" || tag === "under") {
        opts.sizeOp = tag;
      } else if (tag === "zone") {
        opts.zone = this.strings(args[++i])[0];
      } else if (tag === "originalzone") {
        // keep zone of the header date - approximated as UTC
      } else {
        this.warn(`Tag ':${tag}' is ignored in the dry run`);
      }
    }
    return opts;
  }

  private compare(a: string, b: string, comparator: string): number {
    if (comparator === "i;ascii-numeric") {
      const na = /^\d+/.exec(a);
      const nb = /^\d+/.exec(b);
      if (!na && !nb) return 0;
      if (!na) return 1; // non-numbers are "infinity"
      if (!nb) return -1;
      return Number(na[0]) - Number(nb[0]);
    }
    const x = comparator === "i;octet" ? a : foldAscii(a);
    const y = comparator === "i;octet" ? b : foldAscii(b);
    return x < y ? -1 : x > y ? 1 : 0;
  }

  private relational(cmp: number, rel: string | undefined): boolean {
    switch (rel) {
      case "gt":
        return cmp > 0;
      case "ge":
        return cmp >= 0;
      case "lt":
        return cmp < 0;
      case "le":
        return cmp <= 0;
      case "ne":
        return cmp !== 0;
      default:
        return cmp === 0;
    }
  }

  /** Core string matching; sets match variables on success */
  private match(values: string[], keys: string[], opts: TestOptions): boolean {
    const { matchType, comparator } = opts;

    if (matchType === "count") {
      const count = String(values.length);
      return keys.some(k =>
        this.relational(
          this.compare(count, k, "i;ascii-numeric"),
          opts.relational,
        ),
      );
    }

    for (const value of values) {
      for (const key of keys) {
        switch (matchType) {
          case "is":
            if (this.compare(value, key, comparator) === 0) return true;
            break;
          case "contains": {
            const v = comparator === "i;octet" ? value : foldAscii(value);
            const k = comparator === "i;octet" ? key : foldAscii(key);
            if (v.includes(k)) return true;
            break;
          }
          case "value":
            if (
              this.relational(
                this.compare(value, key, comparator),
                opts.relational,
              )
            ) {
              return true;
            }
            break;
          case "matches": {
            const flags = comparator === "i;octet" ? "s" : "is";
            const m = new RegExp(globToRegex(key), flags).exec(value);
            if (m) {
              this.matchVars = [m[0], ...m.slice(1)];
              return true;
            }
            break;
          }
          case "regex": {
            let re: RegExp;
            try {
              re = new RegExp(
                toBytes(translatePosixRegex(key)),
                comparator === "i;octet" ? "s" : "is",
              );
            } catch (error) {
              this.warn(
                `Invalid regex '${key.slice(0, 60)}': ${error instanceof Error ? error.message : String(error)}`,
              );
              break;
            }
            const m = re.exec(toBytes(value));
            if (m) {
              this.matchVars = m.map(g =>
                g === undefined ? "" : fromBytes(g),
              );
              return true;
            }
            break;
          }
        }
      }
    }
    return false;
  }

  private headerNames(arg: SieveArgument | undefined): string[] {
    return this.strings(arg);
  }

  private envelopeValues(part: string): string[] {
    const env = this.message.envelope;
    const lower = part.toLowerCase();
    if (lower === "from") {
      if (env?.from !== undefined) return [env.from];
      this.warn('envelope "from" approximated from the Return-Path header');
      return getHeaderValues(this.message.headers, "Return-Path").flatMap(
        parseAddressList,
      );
    }
    if (lower === "to") {
      if (env?.to !== undefined) return [env.to];
      this.warn(
        'envelope "to" approximated from Delivered-To/X-Original-To/To headers',
      );
      for (const name of ["Delivered-To", "X-Original-To", "To"]) {
        const values = getHeaderValues(this.message.headers, name).flatMap(
          parseAddressList,
        );
        if (values.length) return values;
      }
    }
    return [];
  }

  private evalTest(test: SieveTest): boolean {
    switch (test.name) {
      case "true":
        return true;
      case "false":
        return false;
      case "not":
        return test.tests[0] ? !this.evalTest(test.tests[0]) : true;
      case "allof":
        return test.tests.every(t => this.evalTest(t));
      case "anyof":
        return test.tests.some(t => this.evalTest(t));
      case "header": {
        const opts = this.parseOptions(test.args);
        const names = this.headerNames(opts.positional[0]);
        const keys = this.strings(opts.positional[1]);
        const values = names.flatMap(n =>
          getHeaderValues(this.message.headers, n),
        );
        return this.match(values, keys, opts);
      }
      case "address": {
        const opts = this.parseOptions(test.args);
        const names = this.headerNames(opts.positional[0]);
        const keys = this.strings(opts.positional[1]);
        const values = names
          .flatMap(n => getHeaderValues(this.message.headers, n))
          .flatMap(parseAddressList)
          .map(a => addressPart(a, opts.addressPart));
        return this.match(values, keys, opts);
      }
      case "envelope": {
        const opts = this.parseOptions(test.args);
        const parts = this.strings(opts.positional[0]);
        const keys = this.strings(opts.positional[1]);
        const values = parts
          .flatMap(p => this.envelopeValues(p))
          .map(a => addressPart(a, opts.addressPart));
        return this.match(values, keys, opts);
      }
      case "exists": {
        const names = this.strings(test.args.find(a => a.type !== "tag"));
        return names.every(
          n => getHeaderValues(this.message.headers, n).length > 0,
        );
      }
      case "size": {
        const opts = this.parseOptions(test.args);
        const limit =
          opts.positional[0]?.type === "number" ? opts.positional[0].value : 0;
        return opts.sizeOp === "under"
          ? this.message.size < limit
          : this.message.size > limit;
      }
      case "body": {
        const opts = this.parseOptions(test.args);
        if (opts.bodyTransform === "content") {
          this.warn("body :content is approximated with the decoded text body");
        }
        const keys = this.strings(opts.positional[0]);
        const value =
          opts.bodyTransform === "raw"
            ? this.message.rawBody
            : this.message.text;
        return this.match([value], keys, opts);
      }
      case "string": {
        const opts = this.parseOptions(test.args);
        const sources = this.strings(opts.positional[0]);
        const keys = this.strings(opts.positional[1]);
        // RFC 5229: empty strings don't count for :count
        const values =
          opts.matchType === "count" ? sources.filter(s => s !== "") : sources;
        return this.match(values, keys, opts);
      }
      case "hasflag": {
        const opts = this.parseOptions(test.args);
        const varNames =
          opts.positional.length > 1
            ? this.strings(opts.positional[0])
            : ["__flags__"];
        const keys = this.strings(opts.positional[opts.positional.length - 1]);
        const flags = varNames.flatMap(v =>
          (this.variables.get(v.toLowerCase()) ?? "")
            .split(/\s+/)
            .filter(Boolean),
        );
        return this.match(flags, keys, opts);
      }
      case "currentdate": {
        const opts = this.parseOptions(test.args);
        const part = this.strings(opts.positional[0])[0] ?? "";
        const keys = this.strings(opts.positional[1]);
        const value = datePart(this.message.now ?? new Date(), part, opts.zone);
        if (value === null) {
          this.warn(`currentdate: date-part '${part}' is not supported`);
          return false;
        }
        return this.match([value], keys, opts);
      }
      case "date": {
        const opts = this.parseOptions(test.args);
        const header = this.strings(opts.positional[0])[0] ?? "";
        const part = this.strings(opts.positional[1])[0] ?? "";
        const keys = this.strings(opts.positional[2]);
        const raw = getHeaderValues(this.message.headers, header)[0];
        const parsed = raw ? new Date(raw) : null;
        if (!parsed || Number.isNaN(parsed.getTime())) {
          return false;
        }
        const value = datePart(parsed, part, opts.zone);
        return value === null ? false : this.match([value], keys, opts);
      }
      case "duplicate":
        this.warn("test 'duplicate' is not simulated (always false)");
        return false;
      default:
        this.warn(
          `Line ${test.line}: test '${test.name}' is not simulated (treated as false)`,
        );
        return false;
    }
  }

  result(): SieveDryRunResult {
    const deliveredTo: string[] = [];
    const redirectedTo: string[] = [];
    let discarded = false;
    for (const action of this.actions) {
      if (action.type === "fileinto" && action.target) {
        deliveredTo.push(action.target);
      } else if (action.type === "keep") {
        deliveredTo.push("INBOX");
      } else if (action.type === "redirect" && action.target) {
        redirectedTo.push(action.target);
      } else if (action.type === "discard") {
        discarded = true;
      }
    }
    if (this.implicitKeep) {
      deliveredTo.push("INBOX");
    }
    const flags = (this.variables.get("__flags__") ?? "")
      .split(/\s+/)
      .filter(Boolean);
    return {
      actions: this.actions,
      implicitKeep: this.implicitKeep,
      deliveredTo: [...new Set(deliveredTo)],
      redirectedTo,
      discarded: discarded && deliveredTo.length === 0,
      flags,
      matched: this.matched,
      stopped: this.stopped,
      ...(this.stoppedAt !== undefined ? { stoppedAt: this.stoppedAt } : {}),
      warnings: [...this.warnings],
    };
  }
}

/** Convenience wrapper: parse, lint and run a script against one message */
export function dryRunSieve(
  script: string,
  message: SieveMessage,
): SieveDryRunResult & { lint: string[] } {
  const interpreter = new SieveInterpreter(script);
  return { ...interpreter.run(message), lint: interpreter.lint() };
}
