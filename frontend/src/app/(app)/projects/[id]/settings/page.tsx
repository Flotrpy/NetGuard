"use client";

import { KeyRound, Link2, ShieldCheck, Trash2, Users } from "lucide-react";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Card, EmptyState, ErrorBanner, PageHeader, Tag } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { SEVERITIES, type ApiToken, type Member, type Policy, type Project, type Severity } from "@/lib/types";

const NONE = "__none__";

export default function ProjectSettingsPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [project, setProject] = useState<Project | null>(null);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [policySaved, setPolicySaved] = useState(false);

  const [projectName, setProjectName] = useState("");
  const [projectDescription, setProjectDescription] = useState("");
  const [savingProject, setSavingProject] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState("");

  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState<"editor" | "viewer">("viewer");

  const [tokenName, setTokenName] = useState("");
  const [tokenScopes, setTokenScopes] = useState<Set<string>>(new Set(["read", "write"]));
  const [tokenExpires, setTokenExpires] = useState("");
  const [newToken, setNewToken] = useState<string | null>(null);

  const [provider, setProvider] = useState<"github" | "gitlab">("github");
  const [externalId, setExternalId] = useState("");
  const [connectToken, setConnectToken] = useState("");
  const [connectResult, setConnectResult] = useState<{ webhook_path: string; webhook_secret: string; note: string } | null>(null);
  const [connecting, setConnecting] = useState(false);

  const load = useCallback(async () => {
    try {
      const [p, pol, tok, mem] = await Promise.all([
        api<Project>(`/api/projects/${id}`),
        api<Policy>(`/api/projects/${id}/policy`),
        api<ApiToken[]>(`/api/projects/${id}/tokens`).catch(() => []),
        api<Member[]>(`/api/projects/${id}/members`).catch(() => []),
      ]);
      setProject(p);
      setPolicy(pol);
      setTokens(tok);
      setMembers(mem);
      setProjectName((cur) => cur || p.name);
      setProjectDescription((cur) => cur || p.description);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load settings");
    }
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  const isOwner = project?.role === "owner";

  async function savePolicy(e: FormEvent) {
    e.preventDefault();
    if (!policy) return;
    setSavingPolicy(true);
    setError(null);
    setPolicySaved(false);
    try {
      const saved = await api<Policy>(`/api/projects/${id}/policy`, { method: "PUT", body: policy });
      setPolicy(saved);
      setPolicySaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save policy");
    } finally {
      setSavingPolicy(false);
    }
  }

  async function createToken(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const body = {
        name: tokenName,
        scopes: [...tokenScopes],
        expires_days: tokenExpires ? Number(tokenExpires) : null,
      };
      const created = await api<ApiToken & { token: string }>(`/api/projects/${id}/tokens`, { method: "POST", body });
      setNewToken(created.token);
      setTokenName("");
      setTokenExpires("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create token");
    }
  }

  async function revokeToken(tokenId: string) {
    setError(null);
    try {
      await api(`/api/projects/${id}/tokens/${tokenId}`, { method: "DELETE" });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke token");
    }
  }

  async function connectRepository(e: FormEvent) {
    e.preventDefault();
    setConnecting(true);
    setError(null);
    setConnectResult(null);
    try {
      const res = await api<{ webhook_path: string; webhook_secret: string; note: string }>(
        `/api/projects/${id}/repositories/connect`,
        { method: "POST", body: { provider, external_id: externalId, token: connectToken } },
      );
      setConnectResult(res);
      setExternalId("");
      setConnectToken("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not connect repository");
    } finally {
      setConnecting(false);
    }
  }

  async function saveProject(e: FormEvent) {
    e.preventDefault();
    setSavingProject(true);
    setError(null);
    try {
      const updated = await api<Project>(`/api/projects/${id}`, {
        method: "PATCH",
        body: { name: projectName, description: projectDescription },
      });
      setProject(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save project");
    } finally {
      setSavingProject(false);
    }
  }

  async function deleteProject() {
    if (confirmDelete !== project?.name) return;
    setDeleting(true);
    setError(null);
    try {
      await api(`/api/projects/${id}`, { method: "DELETE" });
      router.push("/projects");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete project");
      setDeleting(false);
    }
  }

  async function addMember(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api(`/api/projects/${id}/members`, {
        method: "POST",
        body: { email: memberEmail, role: memberRole },
      });
      setMemberEmail("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add member");
    }
  }

  async function removeMember(userId: string) {
    setError(null);
    try {
      await api(`/api/projects/${id}/members/${userId}`, { method: "DELETE" });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove member");
    }
  }

  if (!project || !policy) return error ? <ErrorBanner message={error} /> : null;

  if (!isOwner) {
    return (
      <>
        <PageHeader title="Settings" subtitle={project.name} />
        <EmptyState
          title="Owner access required"
          hint="Only a project owner can view or change the security gate policy, CI tokens and repository connections."
        />
      </>
    );
  }

  return (
    <>
      <PageHeader title="Settings" subtitle={project.name} />
      <ErrorBanner message={error} />

      <Card title="Project details">
        <form onSubmit={saveProject} className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Name</span>
            <input className="input" required value={projectName} onChange={(e) => setProjectName(e.target.value)} />
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Description</span>
            <input className="input" value={projectDescription} onChange={(e) => setProjectDescription(e.target.value)} />
          </label>
          <button className="btn btn-primary" disabled={savingProject}>
            {savingProject ? "Saving…" : "Save"}
          </button>
        </form>
      </Card>

      <Card title="Team members" className="mt-6" action={<Users className="h-4 w-4 text-muted" aria-hidden />}>
        <ul className="mb-4 divide-y divide-border">
          {members.map((m) => (
            <li key={m.user_id} className="flex items-center justify-between py-2 text-sm">
              <span>
                <span className="font-medium">{m.name || m.email}</span> <span className="text-muted">{m.email}</span>{" "}
                <Tag>{m.role}</Tag>
              </span>
              {m.role !== "owner" && (
                <button className="btn" onClick={() => removeMember(m.user_id)}>
                  <Trash2 className="h-4 w-4" aria-hidden /> Remove
                </button>
              )}
            </li>
          ))}
        </ul>
        <form onSubmit={addMember} className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Email</span>
            <input className="input" type="email" required value={memberEmail} onChange={(e) => setMemberEmail(e.target.value)} />
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Role</span>
            <select className="input" value={memberRole} onChange={(e) => setMemberRole(e.target.value as "editor" | "viewer")}>
              <option value="viewer">Viewer</option>
              <option value="editor">Editor</option>
            </select>
          </label>
          <button className="btn btn-primary">Add member</button>
        </form>
      </Card>

      <Card title="Security gate policy" className="mt-6" action={<ShieldCheck className="h-4 w-4 text-muted" aria-hidden />}>
        <p className="mb-4 text-sm text-muted">
          Controls when CI/CD builds fail. Every threshold is optional; leave a field blank to not enforce it.
        </p>
        <form onSubmit={savePolicy} className="grid gap-4 sm:grid-cols-2">
          {(
            [
              ["max_critical", "Max Critical findings (all)"],
              ["max_high", "Max High findings (all)"],
              ["max_new_high", "Max NEW High findings"],
              ["max_new_medium", "Max NEW Medium findings"],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="text-sm">
              <span className="mb-1 block text-xs text-muted">{label}</span>
              <input
                className="input"
                type="number"
                min={0}
                placeholder="not enforced"
                value={policy[key] ?? ""}
                onChange={(e) =>
                  setPolicy({ ...policy, [key]: e.target.value === "" ? null : Number(e.target.value) })
                }
              />
            </label>
          ))}
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Fail if ANY finding is at least</span>
            <select
              className="input"
              value={policy.fail_on_severity ?? NONE}
              onChange={(e) => setPolicy({ ...policy, fail_on_severity: e.target.value === NONE ? null : (e.target.value as Severity) })}
            >
              <option value={NONE}>not enforced</option>
              {SEVERITIES.filter((s) => s !== "info").map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Minimum confidence to count</span>
            <select
              className="input"
              value={policy.min_confidence}
              onChange={(e) => setPolicy({ ...policy, min_confidence: e.target.value as Policy["min_confidence"] })}
            >
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm sm:col-span-2">
            <input
              type="checkbox"
              checked={policy.fail_on_secrets}
              onChange={(e) => setPolicy({ ...policy, fail_on_secrets: e.target.checked })}
            />
            Fail the build if any secret is detected
          </label>
          <div className="flex items-center gap-3 sm:col-span-2">
            <button className="btn btn-primary" disabled={savingPolicy}>
              {savingPolicy ? "Saving…" : "Save policy"}
            </button>
            {policySaved && <span className="text-sm text-ok">Saved.</span>}
          </div>
        </form>
      </Card>

      <Card title="CI tokens" className="mt-6" action={<KeyRound className="h-4 w-4 text-muted" aria-hidden />}>
        <p className="mb-4 text-sm text-muted">
          Tokens authenticate <code>netguard-cli</code> and webhook-triggered scans. Each is shown once at creation.
        </p>
        {newToken && (
          <div className="mb-4 rounded-md border border-ok/40 bg-ok/10 px-3 py-2 text-sm">
            <p className="mb-1 font-medium">Copy this token now — it will not be shown again:</p>
            <code className="block break-all rounded bg-surface-2 px-2 py-1 text-xs">{newToken}</code>
          </div>
        )}
        {tokens.length === 0 ? (
          <p className="mb-4 text-sm text-muted">No CI tokens yet.</p>
        ) : (
          <ul className="mb-4 divide-y divide-border">
            {tokens.map((t) => (
              <li key={t.id} className="flex items-center justify-between py-2 text-sm">
                <span>
                  <span className="font-medium">{t.name}</span>{" "}
                  <Tag>{t.prefix}…</Tag> <Tag>{t.scopes.join(", ")}</Tag>{" "}
                  {t.revoked && <Tag className="text-sev-critical">revoked</Tag>}
                  <span className="block text-xs text-muted">
                    Created {timeAgo(t.created_at)}
                    {t.expires_at ? ` · expires ${timeAgo(t.expires_at)}` : ""}
                    {t.last_used ? ` · last used ${timeAgo(t.last_used)}` : " · never used"}
                  </span>
                </span>
                {!t.revoked && (
                  <button className="btn" onClick={() => revokeToken(t.id)}>
                    <Trash2 className="h-4 w-4" aria-hidden /> Revoke
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={createToken} className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Name</span>
            <input className="input" required value={tokenName} onChange={(e) => setTokenName(e.target.value)} />
          </label>
          <label className="flex items-center gap-2 pb-2 text-sm">
            <input
              type="checkbox"
              checked={tokenScopes.has("write")}
              onChange={(e) => {
                const next = new Set(tokenScopes);
                if (e.target.checked) next.add("write");
                else next.delete("write");
                next.add("read");
                setTokenScopes(next);
              }}
            />
            Write access (start scans)
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Expires in (days)</span>
            <input
              className="input"
              type="number"
              min={1}
              placeholder="never"
              value={tokenExpires}
              onChange={(e) => setTokenExpires(e.target.value)}
            />
          </label>
          <button className="btn btn-primary">Create token</button>
        </form>
      </Card>

      <Card title="Connect a repository" className="mt-6" action={<Link2 className="h-4 w-4 text-muted" aria-hidden />}>
        <p className="mb-4 text-sm text-muted">
          Connect a GitHub or GitLab repository you are authorized to access. The access token you provide is
          encrypted at rest and used only to fetch source for scanning.
        </p>
        {connectResult && (
          <div className="mb-4 rounded-md border border-ok/40 bg-ok/10 px-3 py-2 text-sm">
            <p className="mb-1">{connectResult.note}</p>
            <p>
              Webhook URL: <code>{connectResult.webhook_path}</code>
            </p>
            <p>
              Webhook secret: <code className="break-all">{connectResult.webhook_secret}</code>
            </p>
          </div>
        )}
        <form onSubmit={connectRepository} className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Provider</span>
            <select className="input" value={provider} onChange={(e) => setProvider(e.target.value as "github" | "gitlab")}>
              <option value="github">GitHub</option>
              <option value="gitlab">GitLab</option>
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Repository (owner/repo or project ID)</span>
            <input className="input" required value={externalId} onChange={(e) => setExternalId(e.target.value)} />
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">Access token</span>
            <input
              className="input"
              type="password"
              required
              minLength={8}
              value={connectToken}
              onChange={(e) => setConnectToken(e.target.value)}
            />
          </label>
          <button className="btn btn-primary" disabled={connecting}>
            {connecting ? "Connecting…" : "Connect"}
          </button>
        </form>
      </Card>

      <Card title="Danger zone" className="mt-6 border-sev-critical/40">
        <p className="mb-3 text-sm text-muted">
          Deleting a project permanently removes its repositories, scans and findings. This cannot be undone.
        </p>
        <label className="mb-3 block text-sm">
          <span className="mb-1 block text-xs text-muted">Type “{project.name}” to confirm</span>
          <input className="input" value={confirmDelete} onChange={(e) => setConfirmDelete(e.target.value)} />
        </label>
        <button
          className="btn border-sev-critical/40 text-sev-critical"
          disabled={deleting || confirmDelete !== project.name}
          onClick={deleteProject}
        >
          <Trash2 className="h-4 w-4" aria-hidden /> {deleting ? "Deleting…" : "Delete project"}
        </button>
      </Card>
    </>
  );
}
