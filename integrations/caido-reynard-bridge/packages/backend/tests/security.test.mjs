import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { runInNewContext } from "node:vm";
import { EventEmitter } from "node:events";
import ts from "typescript";

const require = createRequire(import.meta.url);
function loadModule(name, mocks = {}) {
  const source = readFileSync(new URL(`../src/${name}.ts`, import.meta.url), "utf8");
  const output = ts.transpileModule(source, { compilerOptions: {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS,
  }}).outputText;
  const exports = {};
  runInNewContext(output, { exports, require: (id) => mocks[id] ?? require(id), setTimeout, clearTimeout });
  return exports;
}
const { parseRequest, authorizeRequest, httpResponse, rememberSession, RequestError } = loadModule("security");
const token = "s".repeat(32);
const wire = (body = "", extras = "") =>
  `POST /replay/raw HTTP/1.1\r\nHost: 127.0.0.1:17650\r\nAuthorization: Bearer ${token}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n${extras}\r\n${Buffer.from(body).toString("latin1")}`;

test("replay cache is bounded and replacing an entry does not evict another", () => {
  const sessions = new Map();
  for (let index = 0; index < 100; index++) rememberSession(sessions, String(index), index);
  rememberSession(sessions, "99", "updated");
  assert.equal(sessions.size, 100); assert.ok(sessions.has("0"));
  rememberSession(sessions, "100", "new");
  assert.equal(sessions.size, 100); assert.ok(!sessions.has("0"));
  assert.equal(sessions.get("99"), "updated");
});

test("UTF-8 content lengths and fragmented bodies remain exact", () => {
  const request = wire('{"message":"café 中文"}');
  assert.equal(parseRequest(request.slice(0, -1)), undefined);
  assert.equal(parseRequest(request).body, '{"message":"café 中文"}');
  const response = httpResponse(200, { message: "café 中文" });
  const [headers, body] = response.split("\r\n\r\n");
  assert.ok(headers.includes(`Content-Length: ${Buffer.byteLength(body)}`));
  assert.ok(!response.includes("Access-Control-Allow-Origin"));
});

test("authentication fails closed; loopback Host and non-browser clients required", () => {
  const request = parseRequest(wire("{}"));
  assert.doesNotThrow(() => authorizeRequest(request, token));
  for (const configured of [undefined, "", "short"]) {
    assert.throws(() => authorizeRequest(request, configured), (error) => error.status === 503);
  }
  for (const auth of [undefined, "", `Bearer ${token}x`, `Bearer ${token.slice(1)}`]) {
    assert.throws(() => authorizeRequest({ ...request, headers: { ...request.headers, authorization: auth } }, token),
      (error) => error.status === 401);
  }
  for (const headers of [{ origin: "null" }, { origin: "http://localhost:17650" },
      { host: "evil.invalid" }, { "sec-fetch-site": "cross-site" }]) {
    assert.throws(() => authorizeRequest({ ...request, headers: { ...request.headers, ...headers } }, token),
      (error) => error.status === 403);
  }
});

test("ambiguous framing, duplicate headers, pipelining, and oversized inputs rejected", () => {
  for (const raw of [
    wire("{}", "Content-Length: 2\r\n"), wire("{}", "Transfer-Encoding: chunked\r\n"),
    wire("{}").replace("Content-Length: 2", "Content-Length: -1"),
    wire("{}").replace("Content-Length: 2", "Content-Length: 2junk"),
    wire("{}") + wire("{}"), wire("{}").replace("POST /replay", "POST //replay"),
    wire("{}", " Authorization: extra\r\n"),
  ]) assert.throws(() => parseRequest(raw), RequestError);
  assert.throws(() => parseRequest("x".repeat(16385)), (error) => error.status === 431);
  assert.throws(() => parseRequest(wire("{}").replace("Content-Length: 2", "Content-Length: 1048577")),
    (error) => error.status === 413);
});

test("entrypoint authenticates before SDK and claims a request only once", async () => {
  let listener, sends = 0, release;
  class RawSpec {
    setHost(value) { this.host = value; } setPort(value) { this.port = value; }
    setTls(value) { this.tls = value; } setRaw(value) { this.raw = value; }
  }
  const net = { createServer: (cb) => {
    listener = cb;
    return { on() {}, listen(_port, _host, cb) { cb(); } };
  }};
  const sdk = { api: { register() {} }, env: { getVar: () => token },
    console: { log() {}, error() {} }, requests: { send: () => {
      sends += 1; return new Promise((resolve) => { release = () => resolve({ request: {}, response: undefined }); });
    } } };
  const entry = loadModule("index", { "caido:utils": { RequestSpecRaw: RawSpec }, net,
    "./security": { parseRequest, authorizeRequest, httpResponse, RequestError } });
  entry.init(sdk);
  const socket = () => {
    const value = new EventEmitter(); value.output = "";
    value.write = (data) => { value.output += data; };
    value.end = () => value.emit("close"); listener(value); return value;
  };
  const denied = socket();
  denied.emit("data", Buffer.from(wire("{}").replace(`Bearer ${token}`, "Bearer wrong"), "latin1"));
  assert.match(denied.output, /401 ERROR/); assert.equal(sends, 0);
  const allowed = socket();
  const raw = wire(JSON.stringify({ hostname: "fixture.invalid", raw_request: "GET / HTTP/1.1\r\n\r\n" }));
  allowed.emit("data", Buffer.from(raw, "latin1"));
  allowed.emit("data", Buffer.from("extra bytes", "latin1"));
  assert.equal(sends, 1); release();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(allowed.output.split("HTTP/1.1").length - 1, 1);
});
