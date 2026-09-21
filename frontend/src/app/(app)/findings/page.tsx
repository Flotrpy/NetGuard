"use client";

import { ChevronLeft, ChevronRight, Search } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { Card, EmptyState, ErrorBanner, PageHeader, SeverityBadge, Spinner, StatusBadge, Tag } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { SEVERITIES, STATUS_LABELS, type FindingPage, type FindingStatus, type Project } from "@/lib/types";

const PAGE_SIZE = 25;
const SORTS: [string, string][] = [
  ["severity", "Severity"],
  ["risk", "Risk score"],
  ["last_seen", "Last seen"],
  ["first_seen", "First seen"],
  ["file", "File"],
  ["status", "Status"],
];

interface Facets {
  language: string[];
  category: string[];
  scanner: string[];
}

function FindingsView() {
  const router = useRouter();
  const params = useSearchParams();
  const [page, setPage] = useState<FindingPage | null>(null);
  const [facets, setFacets] = useState<Facets | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState(params.get("q") ?? "");

  const get = (k: string) => params.get(k) ?? "";
  const offset = Number(get("offset") || 0);
  const severities = get("severity").split(",").filter(Boolean);

  function update(changes: Record<string, string | null>) {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("offset" in changes)) next.delete("offset");
    router.replace(`/findings?${next.toString()}`);
  }

  useEffect(() => {
    api<Project[]>("/api/projects").then(setProjects).catch(() => undefined);
  }, []);

  useEffect(() => {
    api<Facets>("/api/findings/facets", { query: { project_id: get("project_id") } })
      .then(setFacets)
      .catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.get("project_id")]);

  useEffect(() => {
    setPage(null);
    setError(null);
    api<FindingPage>("/api/findings", {
      query: {
        project_id: get("project_id"),
        severity: get("severity"),
        status: get("status"),
        scanner: get("scanner"),
        language: get("language"),
        category: get("category"),
        file: get("file"),
        q: get("q"),
        sort: get("sort") || "severity",
        order: get("order") || "desc",
        limit: PAGE_SIZE,
        offset,
      },
    })
      .then(setPage)
      .catch((e) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.toString()]);

  function toggleSeverity(s: string) {
    const next = severities.includes(s) ? severities.filter((x) => x !== s) : [...severities, s];
    update({ severity: next.join(",") || null });
  }

  return (
    <>
      <PageHeader title="Findings" subtitle="Every issue from every scanner, in one place." />
      <ErrorBanner message={error} />

      <Card className="mb-4">
        <form
          className="mb-3 flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            update({ q: search || null });
          }}
        >
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2 h-4 w-4 text-muted" aria-hidden />
            <input
              className="input pl-8"
              placeholder="Search title, file, rule, CWE…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search findings"
            />
          </div>
          <button className="btn">Search</button>
        </form>

        <div className="mb-3 flex flex-wrap items-center gap-2" role="group" aria-label="Severity filter">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => toggleSeverity(s)}
              aria-pressed={severities.includes(s)}
              className={`rounded transition ${severities.includes(s) ? "ring-2 ring-accent" : "opacity-70 hover:opacity-100"}`}
            >
              <SeverityBadge severity={s} />
            </button>
          ))}
        </div>

        <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-6">
          <Select label="Project" value={get("project_id")} onChange={(v) => update({ project_id: v || null })}
            options={projects.map((p) => [p.id, p.name])} />
          <Select label="Status" value={get("status")} onChange={(v) => update({ status: v || null })}
            options={Object.entries(STATUS_LABELS)} />
          <Select label="Source" value={get("scanner")} onChange={(v) => update({ scanner: v || null })}
            options={(facets?.scanner ?? []).map((s) => [s, s])} />
          <Select label="Language" value={get("language")} onChange={(v) => update({ language: v || null })}
            options={(facets?.language ?? []).map((s) => [s, s])} />
          <Select label="Type" value={get("category")} onChange={(v) => update({ category: v || null })}
            options={(facets?.category ?? []).map((s) => [s, s])} />
          <div>
            <label className="label" htmlFor="ffile">
              File contains
            </label>
            <input id="ffile" className="input" value={get("file")} onChange={(e) => update({ file: e.target.value || null })} />
          </div>
        </div>
        <div className="mt-3 flex items-center gap-2 text-sm">
          <label className="text-muted" htmlFor="fsort">
            Sort by
          </label>
          <select id="fsort" className="input w-40" value={get("sort") || "severity"} onChange={(e) => update({ sort: e.target.value })}>
            {SORTS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
          <button className="btn" onClick={() => update({ order: (get("order") || "desc") === "desc" ? "asc" : "desc" })}>
            {(get("order") || "desc") === "desc" ? "Descending" : "Ascending"}
          </button>
          <button className="btn ml-auto" onClick={() => { setSearch(""); router.replace("/findings"); }}>
            Clear filters
          </button>
        </div>
      </Card>

      {!page ? (
        <Spinner />
      ) : page.items.length === 0 ? (
        <Card>
          <EmptyState title="No findings match" hint="Adjust the filters, or run a scan from a project page." />
        </Card>
      ) : (
        <>
          <div className="card overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="th">Severity</th>
                  <th className="th">Finding</th>
                  <th className="th">Location</th>
                  <th className="th">Source</th>
                  <th className="th">Confidence</th>
                  <th className="th">Risk</th>
                  <th className="th">Status</th>
                  <th className="th">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((f) => (
                  <tr key={f.id} className="border-b border-border last:border-0 hover:bg-surface-2/60">
                    <td className="td">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="td">
                      <Link href={`/findings/${f.id}`} className="font-medium hover:text-accent">
                        {f.title}
                      </Link>
                      {f.cwe && <span className="ml-2"><Tag>{f.cwe}</Tag></span>}
                    </td>
                    <td className="td font-mono text-xs">
                      {f.file_path ? `${f.file_path}${f.line ? `:${f.line}` : ""}` : f.asset ?? "–"}
                    </td>
                    <td className="td text-xs">{f.detection_source}</td>
                    <td className="td text-xs capitalize">{f.confidence}</td>
                    <td className="td tabular-nums">{f.risk_score.toFixed(1)}</td>
                    <td className="td">
                      <StatusBadge status={f.status as FindingStatus} />
                    </td>
                    <td className="td text-xs text-muted">{timeAgo(f.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center justify-between text-sm text-muted">
            <span>
              {offset + 1}–{Math.min(offset + PAGE_SIZE, page.total)} of {page.total}
            </span>
            <div className="flex gap-2">
              <button className="btn" disabled={offset === 0} onClick={() => update({ offset: String(Math.max(0, offset - PAGE_SIZE)) })}>
                <ChevronLeft className="h-4 w-4" aria-hidden /> Prev
              </button>
              <button className="btn" disabled={offset + PAGE_SIZE >= page.total} onClick={() => update({ offset: String(offset + PAGE_SIZE) })}>
                Next <ChevronRight className="h-4 w-4" aria-hidden />
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );
}

function Select({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
}) {
  return (
    <div>
      <label className="label">{label}</label>
      <select className="input" value={value} onChange={(e) => onChange(e.target.value)} aria-label={label}>
        <option value="">Any</option>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </div>
  );
}

export default function FindingsPage() {
  return (
    <Suspense fallback={<Spinner />}>
      <FindingsView />
    </Suspense>
  );
}
