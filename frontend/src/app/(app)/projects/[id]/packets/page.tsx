"use client";

import { Upload } from "lucide-react";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Card, EmptyState, ErrorBanner, PageHeader, Spinner, Tag } from "@/components/ui";
import { api } from "@/lib/api";
import { formatBytes, timeAgo } from "@/lib/format";

interface Capabilities {
  import: { available: boolean; formats: string[]; max_mb: number; max_packets: number };
  live_capture: { available: boolean; reason: string };
  authorization_text: string;
}

interface Capture {
  id: string;
  project_id: string;
  filename: string;
  size_bytes: number;
  packet_count: number;
  sha256: string;
  created_at: string;
  scan_id: string | null;
  scan_status: string | null;
  summary: Record<string, unknown>;
}

interface PacketRow {
  n: number;
  time: number;
  source: string;
  destination: string;
  sport: number;
  dport: number;
  protocol: string;
  length: number;
  info: string;
}

interface PacketDetail extends PacketRow {
  layers: { name: string; fields: [string, string][] }[];
  hex: string;
  truncated_hex: boolean;
}

const PAGE_SIZE = 50;

export default function PacketAnalyzerPage() {
  const { id } = useParams<{ id: string }>();
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [statement, setStatement] = useState("");

  const [activeCapture, setActiveCapture] = useState<string | null>(null);
  const [rows, setRows] = useState<PacketRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [protocol, setProtocol] = useState("");
  const [q, setQ] = useState("");
  const [detail, setDetail] = useState<PacketDetail | null>(null);

  const load = useCallback(async () => {
    try {
      const [c, list] = await Promise.all([
        api<Capabilities>("/api/packet-analysis/capabilities"),
        api<Capture[]>(`/api/projects/${id}/packet-captures`),
      ]);
      setCaps(c);
      setCaptures(list);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load packet analyzer");
    }
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  const loadPackets = useCallback(async () => {
    if (!activeCapture) return;
    try {
      const res = await api<{ total: number; items: PacketRow[] }>(
        `/api/packet-captures/${activeCapture}/packets`,
        { query: { protocol, q, offset, limit: PAGE_SIZE } },
      );
      setTotal(res.total);
      setRows(res.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load packets");
    }
  }, [activeCapture, protocol, q, offset]);
  useEffect(() => {
    loadPackets();
  }, [loadPackets]);

  async function upload(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const file = (form.get("file") as File | null) ?? null;
    if (!file || !file.name) return;
    setUploading(true);
    setError(null);
    try {
      form.set("project_id", id);
      form.set("authorized", String(authorized));
      form.set("authorization_statement", statement);
      await api<Capture>("/api/packet-analysis", { method: "POST", form });
      setStatement("");
      setAuthorized(false);
      e.currentTarget.reset();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed");
    } finally {
      setUploading(false);
    }
  }

  async function viewPacket(n: number) {
    if (!activeCapture) return;
    try {
      setDetail(await api<PacketDetail>(`/api/packet-captures/${activeCapture}/packets/${n}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load packet detail");
    }
  }

  if (!caps) return error ? <ErrorBanner message={error} /> : <Spinner />;

  return (
    <>
      <PageHeader title="Packet analyzer" subtitle="Import a capture, browse statistics and search packets" />
      <ErrorBanner message={error} />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Import a capture">
          {!caps.live_capture.available && (
            <p className="mb-3 text-xs text-muted">{caps.live_capture.reason}</p>
          )}
          <form onSubmit={upload} className="space-y-3">
            <input
              type="file"
              name="file"
              required
              accept=".pcap,.pcapng,.cap"
              className="input"
            />
            <div className="rounded-md border border-border bg-surface-2 p-3 text-xs text-muted">
              {caps.authorization_text}
            </div>
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              I confirm I am authorized to analyze this capture.
            </label>
            <textarea
              className="input"
              rows={2}
              required
              minLength={20}
              value={statement}
              onChange={(e) => setStatement(e.target.value)}
              placeholder="Authorization statement (20+ characters)"
            />
            <button className="btn btn-primary" disabled={uploading || !authorized}>
              <Upload className="h-4 w-4" aria-hidden /> {uploading ? "Importing…" : "Import capture"}
            </button>
            <p className="text-xs text-muted">
              Max {caps.import.max_mb} MB, {caps.import.max_packets.toLocaleString()} packets. Formats:{" "}
              {caps.import.formats.join(", ")}.
            </p>
          </form>
        </Card>

        <Card title="Captures">
          {captures.length === 0 ? (
            <p className="text-sm text-muted">No captures imported yet.</p>
          ) : (
            <ul className="divide-y divide-border">
              {captures.map((c) => (
                <li
                  key={c.id}
                  className={`cursor-pointer py-2 text-sm ${activeCapture === c.id ? "font-medium" : ""}`}
                  onClick={() => {
                    setActiveCapture(c.id);
                    setOffset(0);
                    setDetail(null);
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span>{c.filename}</span>
                    <Tag>{c.scan_status ?? "pending"}</Tag>
                  </div>
                  <span className="block text-xs text-muted">
                    {formatBytes(c.size_bytes)} · {c.packet_count.toLocaleString()} packets · {timeAgo(c.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {activeCapture && (
        <Card title="Packets" className="mt-6">
          <div className="mb-3 flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="mb-1 block text-xs text-muted">Protocol</span>
              <input className="input" value={protocol} onChange={(e) => { setOffset(0); setProtocol(e.target.value); }} placeholder="tcp, dns, http…" />
            </label>
            <label className="text-sm">
              <span className="mb-1 block text-xs text-muted">Search</span>
              <input className="input" value={q} onChange={(e) => { setOffset(0); setQ(e.target.value); }} />
            </label>
            <a
              className="btn ml-auto"
              href={`/api/packet-captures/${activeCapture}/export?protocol=${encodeURIComponent(protocol)}&q=${encodeURIComponent(q)}`}
            >
              Export filtered (.pcap)
            </a>
          </div>
          {rows.length === 0 ? (
            <EmptyState title="No packets match" hint="Try clearing the filters, or wait for the scan to finish." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr>
                    <th className="th">#</th>
                    <th className="th">Source</th>
                    <th className="th">Destination</th>
                    <th className="th">Protocol</th>
                    <th className="th">Length</th>
                    <th className="th">Info</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.n} className="cursor-pointer border-t border-border hover:bg-surface-2" onClick={() => viewPacket(r.n)}>
                      <td className="td tabular-nums">{r.n}</td>
                      <td className="td">{r.source}{r.sport ? `:${r.sport}` : ""}</td>
                      <td className="td">{r.destination}{r.dport ? `:${r.dport}` : ""}</td>
                      <td className="td">{r.protocol}</td>
                      <td className="td tabular-nums">{r.length}</td>
                      <td className="td max-w-md truncate">{r.info}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="mt-3 flex items-center justify-between text-sm">
                <span className="text-muted">
                  {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
                </span>
                <div className="flex gap-2">
                  <button className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                    Previous
                  </button>
                  <button className="btn" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
                    Next
                  </button>
                </div>
              </div>
            </div>
          )}
        </Card>
      )}

      {detail && (
        <Card title={`Packet #${detail.n}`} className="mt-6" action={<button className="btn" onClick={() => setDetail(null)}>Close</button>}>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              {detail.layers.map((layer) => (
                <div key={layer.name}>
                  <p className="mb-1 text-sm font-semibold">{layer.name}</p>
                  <dl className="space-y-0.5 text-xs">
                    {layer.fields.map(([k, v]) => (
                      <div key={k} className="flex gap-2">
                        <dt className="w-40 shrink-0 text-muted">{k}</dt>
                        <dd className="break-all">{v}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ))}
            </div>
            <div>
              <p className="mb-1 text-sm font-semibold">Hex dump{detail.truncated_hex ? " (truncated)" : ""}</p>
              <pre className="max-h-96 overflow-auto rounded bg-surface-2 p-2 text-xs">{detail.hex}</pre>
            </div>
          </div>
        </Card>
      )}
    </>
  );
}
