"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import {
  Bot,
  BrainCircuit,
  FileSearch,
  FlaskConical,
  History,
  LayoutDashboard,
  MessagesSquare,
  Monitor,
  Network,
  Plug,
  ScrollText,
  Settings,
  ShieldCheck,
  Siren,
} from "lucide-react";

import { StatusPill } from "@/components/sentivra/badges";
import { ThemeToggle } from "@/components/sentivra/theme-toggle";
import { useApi } from "@/hooks/use-api";
import { cn } from "@/lib/utils";
import type { Health } from "@/types/api";

const NAV: { href: string; label: string; icon: typeof Bot; group: string }[] = [
  { href: "/", label: "Overview", icon: LayoutDashboard, group: "Monitor" },
  { href: "/threats", label: "Threats", icon: Siren, group: "Monitor" },
  { href: "/network", label: "Network", icon: Network, group: "Detect" },
  { href: "/files", label: "Files", icon: FileSearch, group: "Detect" },
  { href: "/messages", label: "Messages", icon: MessagesSquare, group: "Detect" },
  { href: "/prompt-security", label: "Prompt Security", icon: Bot, group: "Detect" },
  { href: "/endpoint", label: "Endpoint", icon: Monitor, group: "Detect" },
  { href: "/models", label: "Models", icon: BrainCircuit, group: "Platform" },
  { href: "/rules", label: "Rules", icon: ScrollText, group: "Platform" },
  { href: "/integrations", label: "Integrations", icon: Plug, group: "Platform" },
  { href: "/audit", label: "Audit Log", icon: History, group: "Platform" },
  { href: "/demo", label: "Demo mode", icon: FlaskConical, group: "Platform" },
  { href: "/settings", label: "Settings", icon: Settings, group: "Platform" },
];

function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

function BackendStatus() {
  const { data, error } = useApi<Health>("/api/v1/health", { refreshInterval: 30_000 });
  if (error) return <StatusPill status="Error" />;
  if (!data) return <span className="text-xs text-muted-foreground">Connecting…</span>;
  return (
    <span className="flex items-center gap-2 text-xs text-muted-foreground">
      Backend <StatusPill status={data.status === "ok" ? "Available" : "Degraded"} />
    </span>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const groups = [...new Set(NAV.map((n) => n.group))];
  return (
    <div className="flex min-h-dvh">
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col border-r bg-sidebar md:flex">
        <Link href="/" className="flex items-center gap-2 border-b px-4 py-4">
          <ShieldCheck className="size-5" aria-hidden />
          <span className="leading-tight">
            <span className="block text-sm font-semibold tracking-[0.18em]">SENTIVRA</span>
            <span className="block text-[11px] text-muted-foreground">One Security Layer. Every Threat.</span>
          </span>
        </Link>
        <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Main">
          {groups.map((group) => (
            <div key={group} className="mb-3">
              <p className="px-2 pb-1 text-[11px] font-medium tracking-wide text-muted-foreground uppercase">{group}</p>
              <ul className="space-y-0.5">
                {NAV.filter((n) => n.group === group).map(({ href, label, icon: Icon }) => (
                  <li key={href}>
                    <Link
                      href={href}
                      aria-current={isActive(pathname, href) ? "page" : undefined}
                      className={cn(
                        "flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-sidebar-foreground/80 hover:bg-sidebar-accent hover:text-sidebar-foreground",
                        isActive(pathname, href) && "bg-sidebar-accent font-medium text-sidebar-foreground",
                      )}
                    >
                      <Icon className="size-4" aria-hidden />
                      {label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <p className="border-t px-4 py-3 text-[11px] text-muted-foreground">
          Demonstration build: local, no automation.
        </p>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b bg-background/85 px-4 py-2.5 backdrop-blur md:px-6">
          <nav className="flex gap-1 overflow-x-auto md:hidden" aria-label="Main (compact)">
            {NAV.map(({ href, label }) => (
              <Link key={href} href={href}
                className={cn("rounded-md px-2 py-1 text-xs whitespace-nowrap", isActive(pathname, href) ? "bg-muted font-medium" : "text-muted-foreground")}>
                {label}
              </Link>
            ))}
          </nav>
          <div className="hidden md:block" />
          <div className="flex shrink-0 items-center gap-3">
            <BackendStatus />
            <ThemeToggle />
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 space-y-6 px-4 py-6 md:px-6">{children}</main>
      </div>
    </div>
  );
}
