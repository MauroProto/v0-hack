# VibeShield

This is a [Next.js](https://nextjs.org) project bootstrapped with [v0](https://v0.app).

## VibeShield MVP

VibeShield is a static security scanner for AI-built Next.js/React apps.

Main flows:

- `/scan` accepts either a public GitHub repo URL or GitHub login for repository selection.
- `/report/[scanId]` renders the real scan report.
- `/api/github/repos` lists repositories for a GitHub-authenticated user.
- `/api/scan/[scanId]/explain` generates AI explanations and patch previews when AI Gateway, Claude/Anthropic, or DeepSeek is configured, and falls back deterministically otherwise.
- `/api/scan/[scanId]/pull-request` creates a real GitHub remediation PR for authenticated scans when the GitHub token can push to the repository.

The scanner never executes repository code, never runs `npm install` inside user projects, never accepts ZIP uploads, and only reads supported text files server-side through GitHub APIs.

Security limits:

- 20 scans per user/identity per UTC month by default.
- Short burst limits protect `/api/scan` and AI explanation generation.
- Reports are owned by a salted request identity and require the same identity that created them.
- GitHub repository scans are bounded by supported text file count, per-file size and total text size.
- Public mode reads only public repositories. GitHub login mode lists and scans repositories through GitHub REST API metadata, tree and blob endpoints.
- Secrets are redacted before responses and before AI prompts.
- PR creation uses the user's GitHub OAuth token, creates a short-lived `vibeshield/scan-*` branch, applies only low-risk automated hygiene fixes, and leaves app-specific auth/rate-limit/code changes as review-required patch previews.

## Supabase persistence

Local development works without Supabase by using an in-memory report store.

For v0/Vercel/Supabase persistence:

1. Connect Supabase in v0/Vercel so env vars are available in Preview/Production.
2. Run `supabase/migrations/0001_vibeshield_scan_reports.sql` in the Supabase SQL editor.
3. Set server-side env vars:

```bash
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=
VIBESHIELD_MONTHLY_SCAN_QUOTA=20
VIBESHIELD_REQUIRE_PERSISTENT_QUOTA=true
VIBESHIELD_IDENTITY_SALT=
```

`SUPABASE_SERVICE_ROLE_KEY` and `VIBESHIELD_IDENTITY_SALT` must stay server-only. The tables have RLS enabled and no public policies; route handlers persist reports and quota counters with the service role key.

## AI provider keys

Do not commit provider keys. Add them in Vercel/v0 environment variables or local `.env.local` only.

VibeShield supports three real AI paths:

- AI Gateway: set `AI_GATEWAY_API_KEY` or use Vercel OIDC, plus `VIBESHIELD_MODEL`.
- Claude/Anthropic: set `VIBESHIELD_AI_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`, and optionally `VIBESHIELD_ANTHROPIC_MODEL`.
- DeepSeek: set `VIBESHIELD_AI_PROVIDER=deepseek`, `DEEPSEEK_API_KEY`, and optionally `VIBESHIELD_DEEPSEEK_MODEL`. The default is `deepseek-v4-pro` with DeepSeek thinking mode enabled.

If `VIBESHIELD_AI_PROVIDER` is not set, the server tries AI Gateway first, then Claude/Anthropic, then DeepSeek. If no provider is configured, scans still run and explanations fall back to deterministic recommendations.

## Built with v0

This repository is linked to a [v0](https://v0.app) project. You can continue developing by visiting the link below -- start new chats to make changes, and v0 will push commits directly to this repo. Every merge to `main` will automatically deploy.

[Continue working on v0 →](https://v0.app/chat/projects/prj_UyIIlNd2ZthT22b4XM6lJrPfxEvc)

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

## Learn More

To learn more, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.
- [v0 Documentation](https://v0.app/docs) - learn about v0 and how to use it.
