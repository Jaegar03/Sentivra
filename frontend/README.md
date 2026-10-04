# SENTIVRA dashboard

Next.js 16 (App Router) + React 19 + TypeScript + Tailwind CSS v4 + shadcn/ui (Base UI) + Recharts, reading the SENTIVRA backend's REST API from the browser with SWR.

## Run

Start the backend first (see the repo README), then:

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
# or a production build
npm run build && npm start
```

The dashboard calls `http://localhost:8000` by default. To point it elsewhere, create `frontend/.env.local`:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

and add the dashboard's origin to `SENTIVRA_CORS_ORIGINS` on the backend. If the dashboard shows "Can't reach the SENTIVRA backend", either the backend isn't running or the origin you opened (`localhost` and `127.0.0.1` count as different origins) isn't in that list.

`NEXT_PUBLIC_API_BASE_URL` is read at build time. It's also the only API origin the dashboard's Content-Security-Policy allows, so rebuild after changing it.

## Sign-in

The backend requires an OAuth2 access token on every call. The dashboard signs in as an API client:

1. Enter client ID `dashboard` and its secret. A development backend prints the secret once, on first start.
2. `lib/auth.ts` exchanges them at `/api/v1/auth/token` (client credentials) and discards the secret.
3. The access token is kept in `sessionStorage`, so it lasts for this tab only.
4. `lib/api.ts` sends the token as `Authorization: Bearer …` on every request.
5. Any `401` (an expired token, or a backend whose keys or clients changed) clears the token and shows the sign-in screen again. **Sign out** in the header does the same and drops cached responses.

No cookies are used, so cross-site request forgery doesn't apply. The page headers (`next.config.ts`) include a Content-Security-Policy whose `connect-src` and `img-src` allow only this origin and the API. Even injected script can't send the token to another host.

## Pages

| Page | What it shows |
|---|---|
| Overview | Security score (formula shown), KPIs, alert timeline, severity, detection sources, categories, recent threats |
| Threats | Alerts with severity/status filters; detail pages explain what, why, evidence, confidence and action, and allow acknowledge/resolve |
| Network | PCAP/CSV upload and the synthetic demo sample, with per-layer results and behavior findings |
| Files | File upload and the EICAR test file |
| Endpoint | Simulated fleet, osquery results upload and log upload |
| Messages | What the Gmail, Telegram and WhatsApp webhooks delivered: sender, subject, extracted URLs, attachment metadata and the body hash (bodies are never stored), plus each connector's status. Says plainly that no detector analyzes message content yet, so a message is never shown as "clean" |
| Prompt Security | States plainly that the detector isn't built, and shows the API's real 501 response |
| Models, Rules, Integrations, Audit Log, Settings | Registry, rule inventory, real integration status, audit trail (with the acting client), connection and session info |
| Demo mode | Runs every available scenario; results are labeled Demo data or Simulated |

## Design rules applied

- **Input labels.** Every result and every alert row carries a LIVE / SIMULATED / DEMO DATA badge.
- **Severity.** Always shown as status color plus icon plus word. MEDIUM and HIGH aren't separable by status color alone, so the word and icon carry the meaning.
- **Charts.**
  - Single-series charts use one validated color.
  - Bars are 24 px thick at most, with rounded data ends.
  - Grids are hairline.
  - Every chart has a table view.
  - A refetch keeps the previous render on screen instead of flashing.
- **Light and dark.** Each mode has its own palette, and the theme toggle is stored in `localStorage`.
