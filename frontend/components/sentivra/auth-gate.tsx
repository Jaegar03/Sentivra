"use client";

import { useState, useSyncExternalStore, type ReactNode, type SubmitEvent } from "react";
import { KeyRound, LogOut, ShieldCheck } from "lucide-react";
import { useSWRConfig } from "swr";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { API_BASE } from "@/lib/api";
import { clearToken, getSession, signIn, subscribe } from "@/lib/auth";

// The session lives in sessionStorage, outside React: subscribe to it.
// undefined = not known yet (server render / hydration), null = signed out.
const clientSnapshot = () => getSession()?.clientId ?? null;
const serverSnapshot = () => undefined;

function useSignedInClient(): string | null | undefined {
  return useSyncExternalStore(subscribe, clientSnapshot, serverSnapshot);
}

function SignIn() {
  const [clientId, setClientId] = useState("dashboard");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: SubmitEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(API_BASE, clientId.trim(), secret.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-dvh items-center justify-center px-4 py-10">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="mb-2 flex items-center gap-2">
            <ShieldCheck className="size-5" aria-hidden />
            <span className="text-sm font-semibold tracking-[0.18em]">SENTIVRA</span>
          </div>
          <CardTitle>Sign in to the dashboard</CardTitle>
          <CardDescription>
            The API requires an OAuth2 client. The dashboard exchanges its client secret for a short-lived access
            token and keeps only the token, for this browser tab.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="client-id" className="text-sm font-medium">Client ID</label>
              <Input id="client-id" value={clientId} onChange={(e) => setClientId(e.target.value)}
                autoComplete="username" spellCheck={false} required />
            </div>
            <div className="space-y-1.5">
              <label htmlFor="client-secret" className="text-sm font-medium">Client secret</label>
              <Input id="client-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)}
                autoComplete="current-password" spellCheck={false} required
                aria-invalid={error ? true : undefined} aria-describedby={error ? "sign-in-error" : "secret-hint"} />
              <p id="secret-hint" className="text-xs text-muted-foreground">
                On first start, a development backend prints the <code>dashboard</code> secret once in its log. Only a
                hash is kept, in <code>.sentivra/clients.json</code>. If you lost the secret, delete that file and
                restart the backend to get a new one.
              </p>
            </div>
            {error ? (
              <p id="sign-in-error" role="alert" className="text-sm text-destructive">{error}</p>
            ) : null}
            <Button type="submit" className="w-full" disabled={busy || !secret.trim()}>
              <KeyRound aria-hidden /> {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

export function AuthGate({ children }: { children: ReactNode }) {
  const client = useSignedInClient();
  if (client === undefined) {
    return <div className="flex min-h-dvh items-center justify-center text-sm text-muted-foreground">Loading…</div>;
  }
  return client === null ? <SignIn /> : <>{children}</>;
}

/** Rows for a <dl>: who this tab is signed in as, what it may do, until when. */
export function SessionDetails() {
  const client = useSignedInClient();
  const session = client ? getSession() : null;
  if (!session) return null;
  return (
    <>
      <dt className="text-muted-foreground">Signed in as</dt><dd className="font-mono text-xs">{session.clientId}</dd>
      <dt className="text-muted-foreground">Token scopes</dt><dd className="font-mono text-xs">{session.scope}</dd>
      <dt className="text-muted-foreground">Token expires</dt>
      <dd>{new Date(session.expiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</dd>
    </>
  );
}

export function SessionMenu() {
  const client = useSignedInClient();
  const { mutate } = useSWRConfig();
  if (!client) return null;

  function signOut() {
    clearToken();
    // Drop cached responses so the next session doesn't show the last one's data.
    void mutate(() => true, undefined, { revalidate: false });
  }

  return (
    <span className="flex items-center gap-1 text-xs text-muted-foreground">
      <span className="hidden sm:inline">Client <span className="font-mono text-foreground">{client}</span></span>
      <Button variant="ghost" size="icon-sm" onClick={signOut} aria-label="Sign out" title="Sign out">
        <LogOut />
      </Button>
    </span>
  );
}
