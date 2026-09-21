import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, errorMessage, readCookie } from "./api";
import { formatBytes, timeAgo, totalCount } from "./format";

describe("readCookie", () => {
  it("finds a cookie by name and decodes it", () => {
    expect(readCookie("b", "a=1; b=hello%20world; c=3")).toBe("hello world");
    expect(readCookie("missing", "a=1")).toBeNull();
  });
});

describe("errorMessage", () => {
  it("handles strings, validation arrays and fallbacks", () => {
    expect(errorMessage("Nope", "x")).toBe("Nope");
    expect(errorMessage([{ msg: "too short" }, { msg: "bad" }], "x")).toBe("too short; bad");
    expect(errorMessage(undefined, "fallback")).toBe("fallback");
  });
});

describe("api()", () => {
  afterEach(() => vi.restoreAllMocks());

  it("sends the CSRF header only on state-changing requests", async () => {
    Object.defineProperty(document, "cookie", { value: "ng_csrf=tok123", configurable: true });
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    await api("/api/x");
    await api("/api/x", { method: "POST", body: { a: 1 } });
    const getHeaders = fetchMock.mock.calls[0][1]?.headers as Record<string, string>;
    const postHeaders = fetchMock.mock.calls[1][1]?.headers as Record<string, string>;
    expect(getHeaders["X-CSRF-Token"]).toBeUndefined();
    expect(postHeaders["X-CSRF-Token"]).toBe("tok123");
    expect(postHeaders["Content-Type"]).toBe("application/json");
  });

  it("throws ApiError with the server detail", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async () => new Response(JSON.stringify({ detail: "Not authenticated" }), { status: 401 }),
    );
    await expect(api("/api/me")).rejects.toMatchObject({ status: 401, message: "Not authenticated" });
    await expect(api("/api/me")).rejects.toBeInstanceOf(ApiError);
  });

  it("serialises query params and skips empty values", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response("{}"));
    await api("/api/findings", { query: { severity: "high", q: "", limit: 10 } });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/findings?severity=high&limit=10");
  });

  it("returns undefined for 204", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(null, { status: 204 }));
    expect(await api("/api/x", { method: "DELETE" })).toBeUndefined();
  });
});

describe("format helpers", () => {
  it("formats bytes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(5 * 1024 ** 2)).toBe("5.0 MB");
  });
  it("formats relative time, treating naive timestamps as UTC", () => {
    const now = Date.parse("2026-01-01T12:00:00Z");
    expect(timeAgo("2026-01-01T11:59:50Z", now)).toBe("just now");
    expect(timeAgo("2026-01-01T11:30:00", now)).toBe("30m ago");
    expect(timeAgo("2025-12-30T12:00:00Z", now)).toBe("2d ago");
    expect(timeAgo(null)).toBe("never");
  });
  it("totals severity counts", () => {
    expect(totalCount({ critical: 1, high: 2, medium: 3, low: 0, info: 1 })).toBe(7);
    expect(totalCount(null)).toBe(0);
  });
});
