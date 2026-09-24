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

## Pages

| Page | What it shows |
|---|---|
| Overview | Security score (formula shown), KPIs, alert timeline, severity, detection sources, categories, recent threats |
| Threats | Alerts with severity/status filters; detail pages explain what, why, evidence, confidence and action, and allow acknowledge/resolve |
| Network | PCAP/CSV upload and the synthetic demo sample, with per-layer results and behavior findings |
| Files | File upload and the EICAR test file |
| Endpoint | Simulated fleet, osquery results upload and log upload |
| Messages, Prompt Security | State plainly that these detectors and connectors aren't built yet |
| Models, Rules, Integrations, Audit Log, Settings | Registry, rule inventory, real integration status, audit trail, connection info |
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
