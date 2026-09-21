"use client";

import { CheckCircle2, HelpCircle, ShieldAlert, Wrench } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { DiffView } from "@/components/diff-view";
import { Card, ErrorBanner, PageHeader, SeverityBadge, Spinner, StatusBadge, Tag } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import {
  STATUS_LABELS,
  type Explanation,
  type FindingDetail,
  type FindingStatus,
  type Patch,
  type Scan,
} from "@/lib/types";

function VerificationBanner({ state, summary }: { state: string; summary?: string }) {
  const map: Record<string, { icon: typeof CheckCircle2; label: string; cls: string }> = {
    verified_fixed: { icon: CheckCircle2, label: "VERIFIED FIXED", cls: "border-ok/40 bg-ok/10 text-ok" },
    still_detected: { icon: ShieldAlert, label: "STILL DETECTED", cls: "border-sev-high/40 bg-sev-high/10 text-sev-high" },
    unable_to_verify: { icon: HelpCircle, label: "UNABLE TO VERIFY", cls: "border-border bg-surface-2 text-muted" },
  };
  const m = map[state];
  if (!m) return null;
  const Icon = m.icon;
  return (
    <div className={`mb-4 flex items-start gap-2 rounded-md border px-3 py-2 text-sm ${m.cls}`} role="status">
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <div>
        <p className="font-semibold">{m.label}</p>
        {summary && <p className="text-fg/80">{summary}</p>}
      </div>
    </div>
  );
}

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [f, setF] = useState<FindingDetail | null>(null);
  const [patches, setPatches] = useState<Patch[]>([]);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [audience, setAudience] = useState<"beginner" | "advanced">("beginner");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [comment, setComment] = useState("");

  const load = useCallback(async () => {
    try {
      const [d, p] = await Promise.all([
        api<FindingDetail>(`/api/findings/${id}`),
        api<Patch[]>(`/api/findings/${id}/patches`),
      ]);
      setF(d);
      setPatches(p);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load finding");
    }
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  async function run<T>(label: string, fn: () => Promise<T>): Promise<T | undefined> {
    setBusy(label);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : `${label} failed`);
    } finally {
      setBusy(null);
    }
  }

  const explain = (refresh = false) =>
    run("Explaining", async () => {
      setExplanation(await api<Explanation>(`/api/findings/${id}/explain`, { method: "POST", body: { audience, refresh } }));
      await load();
    });

  const generateFix = () =>
    run("Generating fix", async () => {
      await api(`/api/findings/${id}/generate-fix`, { method: "POST", body: {} });
      await load();
    });

  const patchAction = (patch: Patch, action: "apply" | "reject") =>
    run(action === "apply" ? "Applying" : "Rejecting", async () => {
      await api(`/api/patches/${patch.id}/${action}`, { method: "POST" });
      await load();
    });

  const verify = (patch?: Patch) =>
    run("Verifying", async () => {
      const r = await api<{ scan_id: string }>(`/api/findings/${id}/validate`, {
        method: "POST",
        body: patch ? { patch_id: patch.id } : {},
      });
      // The rescan runs in the background; poll until it finishes, then reload the verdict.
      for (let i = 0; i < 120; i++) {
        await new Promise((res) => setTimeout(res, 1500));
        const s = await api<Scan>(`/api/scans/${r.scan_id}`);
        if (!["queued", "running"].includes(s.status)) break;
      }
      await load();
    });

  async function setStatus(status: FindingStatus) {
    await run("Updating", async () => {
      await api(`/api/findings/${id}`, { method: "PATCH", body: { status } });
      await load();
    });
  }

  if (!f) return error ? <ErrorBanner message={error} /> : <Spinner />;
  const latest = patches[0];
  const dependency = f.scanner === "dependencies";
  const extra = f.extra as Record<string, unknown>;

  return (
    <>
      <PageHeader
        title={f.title}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <StatusBadge status={f.status} />
            <Tag>{f.detection_source}</Tag>
            {f.cwe && <Tag>{f.cwe}</Tag>}
            <span className="text-xs">confidence {f.confidence} · risk {f.risk_score.toFixed(1)} · rule {f.rule_id}</span>
          </span>
        }
        actions={
          <select className="input w-44" aria-label="Status" value={f.status} onChange={(e) => setStatus(e.target.value as FindingStatus)}>
            {Object.entries(STATUS_LABELS).map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        }
      />
      <ErrorBanner message={error} />
      {busy && <p className="mb-3"><Spinner label={busy} /></p>}
      {f.verification !== "none" && <VerificationBanner state={f.verification} summary={latest?.verification.summary} />}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card title="Where it is">
            <p className="font-mono text-sm">
              {f.file_path ? `${f.file_path}${f.line ? `:${f.line}` : ""}` : f.asset ?? "n/a"}
            </p>
            {f.code_context && (
              <pre className="mt-3 overflow-x-auto rounded-md border border-border bg-bg p-3 font-mono text-xs leading-5">{f.code_context}</pre>
            )}
            {dependency && (
              <dl className="mt-3 grid grid-cols-2 gap-2 text-sm">
                <dt className="text-muted">Package</dt>
                <dd>{String(extra.package)} {String(extra.version)}</dd>
                <dt className="text-muted">Advisory</dt>
                <dd>{String(extra.vulnerability)} {extra.cve ? `(${String(extra.cve)})` : ""}</dd>
                <dt className="text-muted">Fixed version</dt>
                <dd>{((extra.fixed_versions as string[]) ?? []).join(", ") || "none published"}</dd>
                <dt className="text-muted">Dependency path</dt>
                <dd className="font-mono text-xs">{((extra.dependency_path as string[]) ?? []).join(" › ")}</dd>
              </dl>
            )}
          </Card>

          <Card
            title="Understand it"
            action={
              <div className="flex items-center gap-2">
                <select className="input w-32 py-1" value={audience} aria-label="Audience" onChange={(e) => setAudience(e.target.value as "beginner" | "advanced")}>
                  <option value="beginner">Beginner</option>
                  <option value="advanced">Advanced</option>
                </select>
                <button className="btn" disabled={!!busy} onClick={() => explain(!!explanation)}>
                  {explanation ? "Refresh" : "Explain this"}
                </button>
              </div>
            }
          >
            {!explanation ? (
              <div className="space-y-3 text-sm">
                <p className="font-medium">What happened?</p>
                <p>{f.description}</p>
                <p className="font-medium">Why does it matter?</p>
                <p>{f.impact}</p>
                <p className="font-medium">Recommended remediation</p>
                <p className="whitespace-pre-line">{f.remediation}</p>
                <p className="text-xs text-muted">This is the detection rule&apos;s own text. Click “Explain this” for a tailored explanation.</p>
              </div>
            ) : (
              <div className="space-y-4 text-sm">
                <div>
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Detected (facts from the scan)</p>
                  <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1">
                    {explanation.detected.map((d) => (
                      <div key={d.label} className="contents">
                        <dt className="text-muted">{d.label}</dt>
                        <dd className="font-mono text-xs">{d.value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
                <div>
                  <p className="font-medium">What happened?</p>
                  <p>{explanation.what_happened}</p>
                </div>
                <div>
                  <p className="font-medium">Why does it matter?</p>
                  <p>{explanation.why_it_matters}</p>
                </div>
                {explanation.inferred.length > 0 && (
                  <div>
                    <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-sev-medium">Inferred (not confirmed by the scan)</p>
                    <ul className="list-disc space-y-1 pl-5">
                      {explanation.inferred.map((x, i) => (
                        <li key={i}>{x}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div>
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-accent">Recommended</p>
                  <ul className="list-disc space-y-1 pl-5">
                    {explanation.recommended.map((x, i) => (
                      <li key={i}>{x}</li>
                    ))}
                  </ul>
                </div>
                <p className="text-xs text-muted">
                  Source: {explanation.source === "ai" ? `AI (${explanation.provider ?? ""} ${explanation.model ?? ""})` : "detection rule"}.{" "}
                  {explanation.notice}
                </p>
              </div>
            )}
          </Card>

          <Card
            title="Fix it"
            action={
              <button className="btn btn-primary" disabled={!!busy} onClick={generateFix}>
                <Wrench className="h-4 w-4" aria-hidden /> {patches.length ? "Generate another" : "Generate fix"}
              </button>
            }
          >
            {patches.length === 0 ? (
              <p className="text-sm text-muted">
                NetGuard proposes a patch as a diff. Nothing changes until you review and apply it, and a fix is only
                “verified” after a rescan.
              </p>
            ) : (
              <div className="space-y-6">
                {patches.map((p) => (
                  <div key={p.id} className="space-y-3">
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <Tag>{p.generator === "ai" ? "AI-generated" : "rule-based"}</Tag>
                      <Tag>{p.status}</Tag>
                      <span className="text-xs text-muted">{timeAgo(p.created_at)}</span>
                    </div>
                    <p className="text-sm">{p.explanation}</p>
                    <DiffView diff={p.diff} />
                    {p.caveats.length > 0 && (
                      <ul className="list-disc space-y-1 rounded-md border border-sev-medium/30 bg-sev-medium/10 py-2 pl-7 pr-3 text-xs">
                        {p.caveats.map((c, i) => (
                          <li key={i}>{c}</li>
                        ))}
                      </ul>
                    )}
                    {p.verification.preflight?.performed && p.status === "proposed" && (
                      <p className="text-xs text-muted">Preview: {p.verification.preflight.note}</p>
                    )}
                    {p.verification.state && p.status === "applied" && (
                      <ul className="space-y-1 text-sm">
                        {(p.verification.checks ?? []).map((c) => (
                          <li key={c.name} className="flex items-center gap-2">
                            {c.passed ? <CheckCircle2 className="h-4 w-4 text-ok" aria-hidden /> : <ShieldAlert className="h-4 w-4 text-sev-high" aria-hidden />}
                            {c.name}
                          </li>
                        ))}
                      </ul>
                    )}
                    <div className="flex gap-2">
                      {p.status === "proposed" && (
                        <>
                          <button className="btn btn-primary" disabled={!!busy} onClick={() => patchAction(p, "apply")}>
                            Apply patch
                          </button>
                          <button className="btn" disabled={!!busy} onClick={() => patchAction(p, "reject")}>
                            Reject
                          </button>
                        </>
                      )}
                      {p.status === "applied" && (
                        <button className="btn btn-primary" disabled={!!busy} onClick={() => verify(p)}>
                          Rescan &amp; verify
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
            {patches.length === 0 && (
              <button className="btn mt-3" disabled={!!busy} onClick={() => verify()}>
                Rescan &amp; verify current code
              </button>
            )}
          </Card>
        </div>

        <div className="space-y-6">
          <Card title="History">
            <ol className="space-y-3 text-sm">
              {f.events.map((e) => (
                <li key={e.id} className="border-l-2 border-border pl-3">
                  <p className="font-medium">{e.message || e.kind}</p>
                  <p className="text-xs text-muted">
                    {e.kind} · {timeAgo(e.created_at)}
                  </p>
                </li>
              ))}
            </ol>
            <form
              className="mt-4 flex gap-2"
              onSubmit={async (ev) => {
                ev.preventDefault();
                if (!comment.trim()) return;
                await run("Commenting", async () => {
                  await api(`/api/findings/${id}/comments`, { method: "POST", body: { message: comment } });
                  setComment("");
                  await load();
                });
              }}
            >
              <input className="input" placeholder="Add a note" value={comment} onChange={(e) => setComment(e.target.value)} aria-label="Add a note" />
              <button className="btn">Add</button>
            </form>
          </Card>
          <Card title="Details">
            <dl className="space-y-2 text-sm">
              <div><dt className="text-xs text-muted">First seen</dt><dd>{timeAgo(f.first_seen)}</dd></div>
              <div><dt className="text-xs text-muted">Last seen</dt><dd>{timeAgo(f.last_seen)}</dd></div>
              <div><dt className="text-xs text-muted">Exploitability</dt><dd>{f.exploitability}</dd></div>
              <div><dt className="text-xs text-muted">Exposure</dt><dd>{f.exposure}</dd></div>
              {f.references.length > 0 && (
                <div>
                  <dt className="text-xs text-muted">References</dt>
                  <dd className="space-y-1">
                    {f.references.map((r) => (
                      <a key={r} href={r} target="_blank" rel="noopener noreferrer" className="block truncate text-accent hover:underline">{r}</a>
                    ))}
                  </dd>
                </div>
              )}
            </dl>
          </Card>
          <Link href={`/findings?project_id=${f.project_id}`} className="btn w-full">Back to findings</Link>
        </div>
      </div>
    </>
  );
}
