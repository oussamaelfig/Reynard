import { Buffer } from "buffer";

export const MAX_BODY_BYTES = 1024 * 1024;
const MAX_HEADER_BYTES = 16384;

export type ParsedRequest = {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
};

export class RequestError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

export function rememberSession<T>(sessions: Map<string, T>, id: string, value: T): void {
  if (!sessions.has(id) && sessions.size >= 100) {
    const oldest = sessions.keys().next().value;
    if (oldest !== undefined) sessions.delete(oldest);
  }
  sessions.set(id, value);
}

/** Input is a latin1 wire string: one character per byte, not decoded UTF-8. */
export function parseRequest(raw: string): ParsedRequest | undefined {
  if (raw.length > MAX_BODY_BYTES + MAX_HEADER_BYTES) {
    throw new RequestError("Request too large", 413);
  }
  const splitAt = raw.indexOf("\r\n\r\n");
  if (splitAt < 0) {
    if (raw.length > MAX_HEADER_BYTES) throw new RequestError("Headers too large", 431);
    return undefined;
  }
  if (splitAt > MAX_HEADER_BYTES) throw new RequestError("Headers too large", 431);
  const lines = raw.slice(0, splitAt).split("\r\n");
  const match = /^(GET|POST|OPTIONS) (\/[^\s#]*) HTTP\/1\.[01]$/.exec(lines.shift() ?? "");
  if (!match || match[2]?.startsWith("//")) throw new RequestError("Invalid request line");
  const headers: Record<string, string> = Object.create(null);
  for (const line of lines) {
    const colon = line.indexOf(":");
    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (colon <= 0 || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) ||
        /[\x00-\x1f\x7f]/.test(value) || name in headers) {
      throw new RequestError("Invalid or duplicate header");
    }
    headers[name] = value;
  }
  if ("transfer-encoding" in headers) throw new RequestError("Chunked requests are not supported");
  const lengthValue = headers["content-length"] ?? "0";
  if (!/^(0|[1-9]\d*)$/.test(lengthValue)) throw new RequestError("Invalid content length");
  const contentLength = Number(lengthValue);
  if (!Number.isSafeInteger(contentLength) || contentLength > MAX_BODY_BYTES) {
    throw new RequestError("Body too large", 413);
  }
  const bodyStart = splitAt + 4;
  if (raw.length < bodyStart + contentLength) return undefined;
  if (raw.length !== bodyStart + contentLength) throw new RequestError("Pipelining is not supported");
  return {
    method: match[1]!, path: match[2]!, headers,
    body: Buffer.from(raw.slice(bodyStart), "latin1").toString("utf8"),
  };
}

/** No browser origin is trusted; the bridge is a local authenticated API. */
export function authorizeRequest(request: ParsedRequest, token: string | undefined): void {
  if (!["127.0.0.1:17650", "localhost:17650", "[::1]:17650"].includes(request.headers.host ?? "")) {
    throw new RequestError("Loopback Host required", 403);
  }
  if ("origin" in request.headers || request.headers["sec-fetch-site"] === "cross-site") {
    throw new RequestError("Browser origins are not permitted", 403);
  }
  if (!token || token.trim().length < 32) {
    throw new RequestError("Set CAIDO_LOCAL_BRIDGE_TOKEN (at least 32 characters) in Caido environment variables", 503);
  }
  const expected = `Bearer ${token}`;
  const supplied = request.headers.authorization ?? "";
  let different = expected.length ^ supplied.length;
  for (let index = 0; index < expected.length; index++) {
    different |= expected.charCodeAt(index) ^ (supplied.charCodeAt(index) || 0);
  }
  if (different !== 0) throw new RequestError("Invalid or missing bridge token", 401);
  if (request.method === "POST" &&
      request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase() !== "application/json") {
    throw new RequestError("application/json is required", 415);
  }
}

export function httpResponse(status: number, body: Record<string, unknown>): string {
  const payload = JSON.stringify(body);
  return [
    `HTTP/1.1 ${status} ${status < 300 ? "OK" : "ERROR"}`,
    "Content-Type: application/json; charset=utf-8",
    "Cache-Control: no-store",
    "X-Content-Type-Options: nosniff",
    `Content-Length: ${Buffer.byteLength(payload, "utf8")}`,
    "Connection: close", "", payload,
  ].join("\r\n");
}
