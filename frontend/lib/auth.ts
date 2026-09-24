// Dashboard sign-in: the OAuth2 client-credentials exchange, done once.
//
// The client secret is used for a single token request and never stored.
// Only the short-lived access token is kept, in sessionStorage, so it goes
// away when the tab closes. A 401 from the API clears it (see lib/api.ts).

const KEY = "sentivra-token";
const EVENT = "sentivra:auth-changed";

interface StoredToken {
  token: string;
  expiresAt: number; // epoch ms
  clientId: string;
  scope: string;
}

function read(): StoredToken | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as StoredToken;
    return parsed.expiresAt > Date.now() + 5_000 ? parsed : null;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return typeof window === "undefined" ? null : read()?.token ?? null;
}

export function getSession(): Omit<StoredToken, "token"> | null {
  const t = typeof window === "undefined" ? null : read();
  return t ? { expiresAt: t.expiresAt, clientId: t.clientId, scope: t.scope } : null;
}

export function clearToken(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    // storage unavailable: nothing to clear
  }
  window.dispatchEvent(new Event(EVENT));
}

/** For useSyncExternalStore: fires on sign-in, sign-out and expiry-driven 401s. */
export function subscribe(onChange: () => void): () => void {
  window.addEventListener(EVENT, onChange);
  window.addEventListener("storage", onChange);
  return () => {
    window.removeEventListener(EVENT, onChange);
    window.removeEventListener("storage", onChange);
  };
}

export async function signIn(apiBase: string, clientId: string, clientSecret: string): Promise<void> {
  const body = new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret });
  let response: Response;
  try {
    response = await fetch(`${apiBase}/api/v1/auth/token`, { method: "POST", body });
  } catch {
    throw new Error(`Can't reach the SENTIVRA backend at ${apiBase}.`);
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      response.status === 401
        ? "That client ID and secret weren't accepted."
        : response.status === 429
          ? "Too many sign-in attempts. Wait a minute and try again."
          : data.error_description ?? `Sign-in failed (${response.status}).`,
    );
  }
  const stored: StoredToken = {
    token: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
    clientId,
    scope: data.scope,
  };
  sessionStorage.setItem(KEY, JSON.stringify(stored));
  window.dispatchEvent(new Event(EVENT));
}
