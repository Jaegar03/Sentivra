import type { NextConfig } from "next";

// The dashboard keeps an API access token in sessionStorage, so script
// injection is the threat that matters most. This policy is defence in depth
// behind React's escaping:
//   * connect-src allows only this origin and the SENTIVRA API, so an injected
//     script can't send the token to another host with fetch/XHR/WebSocket;
//   * img-src allows only this origin and data: URIs, which blocks
//     image-beacon exfiltration too;
//   * nothing may frame the dashboard, and <base>, <object> and form
//     targets are locked down.
// script-src still needs 'unsafe-inline': statically rendered Next.js pages
// inline their RSC payload, and a nonce would force per-request rendering.
// 'unsafe-eval' is added only for `next dev` (React's dev tooling uses it).
const API_ORIGIN = new URL(process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000").origin;
const DEV = process.env.NODE_ENV === "development";

const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${DEV ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self' ${API_ORIGIN}${DEV ? " ws:" : ""}`,
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
