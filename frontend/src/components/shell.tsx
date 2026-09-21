"use client";

import clsx from "clsx";
import {
  Boxes,
  FileText,
  FolderGit2,
  Globe,
  LayoutDashboard,
  LogOut,
  Network,
  Radar,
  ScanSearch,
  ShieldCheck,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { ThemeToggle } from "@/components/theme-toggle";
import { Spinner, Tag } from "@/components/ui";
import { useAuth } from "@/lib/auth";

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Modules that are designed but not built yet are shown, labelled, and not linked. */
  planned?: boolean;
}

export const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: "Overview",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/projects", label: "Projects", icon: FolderGit2 },
      { href: "/findings", label: "Findings", icon: ScanSearch },
    ],
  },
  {
    section: "Network",
    items: [
      { href: "/network", label: "Network Scanner", icon: Radar, planned: true },
      { href: "/packets", label: "Packet Analyzer", icon: Waypoints, planned: true },
      { href: "/network-map", label: "Network Map", icon: Network, planned: true },
    ],
  },
  {
    section: "More",
    items: [
      { href: "/api-scanner", label: "API Scanner", icon: Globe, planned: true },
      { href: "/containers", label: "Containers & IaC", icon: Boxes, planned: true },
      { href: "/reports", label: "Reports", icon: FileText, planned: true },
    ],
  },
];

export function Shell({ children }: { children: ReactNode }) {
  const { user, loading, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-border bg-surface md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <ShieldCheck className="h-6 w-6 text-accent" aria-hidden />
          <span className="text-lg font-semibold tracking-tight">NetGuard</span>
        </div>
        <nav className="flex-1 space-y-5 overflow-y-auto px-2 py-2" aria-label="Main">
          {NAV.map((group) => (
            <div key={group.section}>
              <p className="px-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-muted">
                {group.section}
              </p>
              {group.items.map((item) => {
                const active = pathname === item.href || pathname.startsWith(item.href + "/");
                const Icon = item.icon;
                const body = (
                  <>
                    <Icon className="h-4 w-4" aria-hidden />
                    <span className="flex-1">{item.label}</span>
                    {item.planned && <Tag>planned</Tag>}
                  </>
                );
                return item.planned ? (
                  <div
                    key={item.href}
                    className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-muted/70"
                    aria-disabled
                    title="Not implemented yet"
                  >
                    {body}
                  </div>
                ) : (
                  <Link
                    key={item.href}
                    href={item.href}
                    aria-current={active ? "page" : undefined}
                    className={clsx(
                      "flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition",
                      active ? "bg-accent/10 text-accent" : "text-fg/80 hover:bg-surface-2",
                    )}
                  >
                    {body}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="border-t border-border p-3">
          <p className="truncate text-sm font-medium">{user.name || user.email}</p>
          <p className="truncate text-xs text-muted">
            {user.email} · {user.role}
          </p>
          <div className="mt-2 flex gap-2">
            <ThemeToggle />
            <button className="btn flex-1" onClick={logout}>
              <LogOut className="h-4 w-4" aria-hidden /> Sign out
            </button>
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 md:px-8">
        <div className="mx-auto max-w-6xl">{children}</div>
      </main>
    </div>
  );
}
