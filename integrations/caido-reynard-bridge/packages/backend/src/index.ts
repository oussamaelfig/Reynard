import type { DefineAPI, SDK } from "caido:plugin";
import { RequestSpecRaw } from "caido:utils";
import * as net from "net";

const CONTRACT = "reynard-caido-local-bridge/v1";
const HOST = "127.0.0.1";
const PORT = 17650;

type JsonRecord = Record<string, unknown>;

type ParsedRequest = {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
};

let bridgeServer: net.Server | undefined;
const replaySessions = new Map<string, unknown>();

const nowIso = () => new Date().toISOString();

function stringToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i += 1) {
    bytes[i] = value.charCodeAt(i) & 0xff;
  }
  return bytes;
}

function bytesToText(bytes: Uint8Array | undefined): string | undefined {
  if (!bytes) {
    return undefined;
  }
  let text = "";
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    text += String.fromCharCode(...bytes.slice(i, i + chunkSize));
  }
  return text;
}

function jsonBody(body: string): JsonRecord {
  if (!body.trim()) {
    return {};
  }
  const parsed: unknown = JSON.parse(body);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("JSON body must be an object");
  }
  return parsed as JsonRecord;
}

function getString(input: JsonRecord, key: string, fallback = ""): string {
  const value = input[key];
  return typeof value === "string" ? value : fallback;
}

function getBoolean(input: JsonRecord, key: string, fallback: boolean): boolean {
  const value = input[key];
  return typeof value === "boolean" ? value : fallback;
}

function getNumber(input: JsonRecord, key: string, fallback: number): number {
  const value = input[key];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function targetUrl(input: JsonRecord): string {
  const hostname = getString(input, "hostname");
  if (!hostname) {
    throw new Error("hostname is required");
  }
  const https = getBoolean(input, "https", true);
  const port = getNumber(input, "port", https ? 443 : 80);
  const scheme = https ? "https" : "http";
  return `${scheme}://${hostname}:${port}/`;
}

function rawSpec(input: JsonRecord): RequestSpecRaw {
  const raw = getString(input, "raw_request");
  if (!raw) {
    throw new Error("raw_request is required");
  }
  const spec = new RequestSpecRaw(targetUrl(input));
  spec.setHost(getString(input, "hostname"));
  spec.setPort(getNumber(input, "port", getBoolean(input, "https", true) ? 443 : 80));
  spec.setTls(getBoolean(input, "https", true));
  spec.setRaw(stringToBytes(raw));
  return spec;
}

function serializeRequest(request: any, includeRaw: boolean): JsonRecord {
  const out: JsonRecord = {
    id: request.getId?.(),
    method: request.getMethod?.(),
    host: request.getHost?.(),
    port: request.getPort?.(),
    path: request.getPath?.(),
    query: request.getQuery?.(),
    tls: request.getTls?.(),
    url: request.getUrl?.(),
    created_at: request.getCreatedAt?.()?.toISOString?.(),
  };
  if (includeRaw) {
    out.raw_request = request.getRaw?.()?.toText?.() ?? bytesToText(request.getRaw?.()?.toBytes?.());
  }
  return out;
}

function serializeResponse(response: any, includeRaw: boolean): JsonRecord | undefined {
  if (!response) {
    return undefined;
  }
  const out: JsonRecord = {
    id: response.getId?.(),
    code: response.getCode?.(),
    headers: response.getHeaders?.(),
    roundtrip_ms: response.getRoundtripTime?.(),
    created_at: response.getCreatedAt?.()?.toISOString?.(),
    body: response.getBody?.()?.toText?.(),
  };
  if (includeRaw) {
    out.raw_response = response.getRaw?.()?.toText?.() ?? bytesToText(response.getRaw?.()?.toBytes?.());
  }
  return out;
}

function ok(body: JsonRecord = {}): JsonRecord {
  return {
    ok: true,
    contract: CONTRACT,
    ...body,
  };
}

function fail(message: string, status = 500, details?: unknown): JsonRecord {
  return {
    ok: false,
    status,
    contract: CONTRACT,
    error: message,
    details,
  };
}

async function handleStatus(): Promise<JsonRecord> {
  return ok({
    reachable: true,
    bridge_url: `http://${HOST}:${PORT}`,
    started_at: nowIso(),
    endpoints: [
      "GET /status",
      "POST /replay/raw",
      "POST /replay/sessions",
      "POST /replay/sessions/{session_id}/send",
      "POST /history/search",
      "GET /history/{request_id}",
      "POST /findings",
    ],
  });
}

async function handleReplayRaw(sdk: SDK, request: ParsedRequest): Promise<JsonRecord> {
  const body = jsonBody(request.body);
  const spec = rawSpec(body);
  const shouldSend = getBoolean(body, "send", true);
  if (!shouldSend) {
    return ok({
      sent: false,
      request: {
        host: spec.getHost(),
        port: spec.getPort(),
        tls: spec.getTls(),
        raw_request: bytesToText(spec.getRaw()),
      },
    });
  }

  const result = await sdk.requests.send(spec, {
    save: true,
    plugins: true,
    timeouts: {
      connect: 30000,
      response: 30000,
      partial: 5000,
      extra: 1000,
    },
  });
  return ok({
    sent: true,
    request: serializeRequest(result.request, true),
    response: serializeResponse(result.response, true),
  });
}

async function handleCreateReplaySession(sdk: SDK, request: ParsedRequest): Promise<JsonRecord> {
  const body = jsonBody(request.body);
  const spec = rawSpec(body);
  const session = await sdk.replay.createSession(spec);
  replaySessions.set(String(session.getId()), spec);
  return ok({
    session_id: session.getId(),
    session_name: session.getName(),
    request: {
      host: spec.getHost(),
      port: spec.getPort(),
      tls: spec.getTls(),
      raw_request: bytesToText(spec.getRaw()),
    },
  });
}

async function handleSendReplaySession(sdk: SDK, sessionId: string): Promise<JsonRecord> {
  const spec = replaySessions.get(sessionId);
  if (!(spec instanceof RequestSpecRaw)) {
    return fail(
      "Replay session was created in Caido, but this bridge can only send sessions it created in the current plugin runtime.",
      404,
    );
  }
  const result = await sdk.requests.send(spec, { save: true, plugins: true });
  return ok({
    session_id: sessionId,
    sent: true,
    request: serializeRequest(result.request, true),
    response: serializeResponse(result.response, true),
  });
}

async function handleHistorySearch(sdk: SDK, request: ParsedRequest): Promise<JsonRecord> {
  const body = jsonBody(request.body);
  const query = getString(body, "query");
  const limit = Math.max(1, Math.min(getNumber(body, "limit", 20), 100));
  const includeResponse = getBoolean(body, "include_response", false);
  let builder = sdk.requests.query().first(limit).descending("req", "created_at");
  if (query) {
    builder = builder.filter(query);
  }
  const page = await builder.execute();
  return ok({
    count: page.items.length,
    page_info: page.pageInfo,
    items: page.items.map((item: any) => ({
      cursor: item.cursor,
      request: serializeRequest(item.request, false),
      response: includeResponse ? serializeResponse(item.response, false) : undefined,
    })),
  });
}

async function handleHistoryItem(sdk: SDK, requestId: string, request: ParsedRequest): Promise<JsonRecord> {
  const includeRaw = request.path.includes("include_response=true");
  const item = await sdk.requests.get(requestId);
  if (!item) {
    return fail(`No Caido request found for id ${requestId}`, 404);
  }
  return ok({
    request: serializeRequest(item.request, true),
    response: serializeResponse(item.response, includeRaw),
  });
}

async function handleFinding(sdk: SDK, request: ParsedRequest): Promise<JsonRecord> {
  const body = jsonBody(request.body);
  const title = getString(body, "title");
  const description = getString(body, "description");
  const requestId = getString(body, "request_id");
  if (!title || !description || !requestId) {
    return fail("title, description, and request_id are required to create a Caido finding", 400);
  }
  const item = await sdk.requests.get(requestId);
  if (!item) {
    return fail(`No Caido request found for id ${requestId}`, 404);
  }
  const severity = getString(body, "severity", "info");
  const finding = await sdk.findings.create({
    title: `[${severity}] ${title}`,
    description: `${description}\n\n${getString(body, "evidence")}`.trim(),
    reporter: "Reynard",
    dedupeKey: `reynard-${requestId}-${title}` as any,
    request: item.request,
  });
  return ok({
    finding_id: finding.getId(),
    title: finding.getTitle(),
    request_id: finding.getRequestId(),
  });
}

async function route(sdk: SDK, request: ParsedRequest): Promise<JsonRecord> {
  const pathOnly = request.path.split("?")[0] ?? request.path;
  if (request.method === "OPTIONS") {
    return ok();
  }
  if (request.method === "GET" && pathOnly === "/status") {
    return handleStatus();
  }
  if (request.method === "POST" && pathOnly === "/replay/raw") {
    return handleReplayRaw(sdk, request);
  }
  if (request.method === "POST" && pathOnly === "/replay/sessions") {
    return handleCreateReplaySession(sdk, request);
  }
  const replaySend = pathOnly.match(/^\/replay\/sessions\/([^/]+)\/send$/);
  if (request.method === "POST" && replaySend?.[1]) {
    return handleSendReplaySession(sdk, decodeURIComponent(replaySend[1]));
  }
  if (request.method === "POST" && pathOnly === "/history/search") {
    return handleHistorySearch(sdk, request);
  }
  const history = pathOnly.match(/^\/history\/([^/]+)$/);
  if (request.method === "GET" && history?.[1]) {
    return handleHistoryItem(sdk, decodeURIComponent(history[1]), request);
  }
  if (request.method === "POST" && pathOnly === "/findings") {
    return handleFinding(sdk, request);
  }
  return fail(`Unknown endpoint ${request.method} ${request.path}`, 404);
}

function parseRequest(raw: string): ParsedRequest | undefined {
  const splitAt = raw.indexOf("\r\n\r\n");
  if (splitAt < 0) {
    return undefined;
  }

  const head = raw.slice(0, splitAt);
  const lines = head.split("\r\n");
  const requestLine = lines.shift();
  if (!requestLine) {
    throw new Error("Missing HTTP request line");
  }
  const [method, path] = requestLine.split(" ");
  if (!method || !path) {
    throw new Error(`Invalid HTTP request line: ${requestLine}`);
  }

  const headers: Record<string, string> = {};
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon > 0) {
      headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
    }
  }

  const contentLength = Number.parseInt(headers["content-length"] ?? "0", 10);
  const bodyStart = splitAt + 4;
  if (raw.length < bodyStart + contentLength) {
    return undefined;
  }

  return {
    method: method.toUpperCase(),
    path,
    headers,
    body: raw.slice(bodyStart, bodyStart + contentLength),
  };
}

function httpResponse(status: number, body: JsonRecord): string {
  const payload = JSON.stringify(body, null, 2);
  const reason = status >= 200 && status < 300 ? "OK" : "ERROR";
  return [
    `HTTP/1.1 ${status} ${reason}`,
    "Content-Type: application/json; charset=utf-8",
    "Access-Control-Allow-Origin: *",
    "Access-Control-Allow-Headers: authorization, content-type",
    "Access-Control-Allow-Methods: GET, POST, OPTIONS",
    `Content-Length: ${payload.length}`,
    "Connection: close",
    "",
    payload,
  ].join("\r\n");
}

function startBridge(sdk: SDK): void {
  if (bridgeServer) {
    return;
  }

  bridgeServer = net.createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk: Uint8Array) => {
      buffer += bytesToText(chunk) ?? "";
      void (async () => {
        try {
          const request = parseRequest(buffer);
          if (!request) {
            return;
          }
          const result = await route(sdk, request);
          const status = typeof result.status === "number" ? result.status : 200;
          socket.write(httpResponse(status, result));
          socket.end();
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          sdk.console.error(`Reynard bridge error: ${message}`);
          socket.write(httpResponse(500, fail(message)));
          socket.end();
        }
      })();
    });
  });

  bridgeServer.on("error", (error) => {
    const message = error instanceof Error ? error.message : String(error);
    sdk.console.error(`Reynard Caido bridge failed on ${HOST}:${PORT}: ${message}`);
  });
  bridgeServer.listen(PORT, HOST, () => {
    sdk.console.log(`Reynard Caido bridge listening on http://${HOST}:${PORT}`);
  });
}

const ping = async (_sdk: SDK): Promise<JsonRecord> => handleStatus();

export type API = DefineAPI<{
  ping: typeof ping;
}>;

export function init(sdk: SDK<API>) {
  sdk.api.register("ping", ping);
  startBridge(sdk);
}
