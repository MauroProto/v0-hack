import "server-only"

import { createSign } from "node:crypto"
import {
  getGitHubAppId,
  getGitHubAppInstallationId,
  getGitHubAppPrivateKey,
  isGitHubAppConfigured,
  isGitHubAppInstallationConfigured,
} from "./github-app-config"

const GITHUB_API = "https://api.github.com"

export { isGitHubAppConfigured }

export async function createDefaultGitHubAppInstallationToken() {
  const installationId = getGitHubAppInstallationId()
  if (!installationId) throw new Error("GitHub App installation id is missing.")
  return createGitHubAppInstallationToken(installationId)
}

export async function createGitHubAppInstallationToken(installationId: string | number) {
  if (!isGitHubAppConfigured()) throw new Error("GitHub App is not configured.")

  const response = await fetch(`${GITHUB_API}/app/installations/${encodeURIComponent(String(installationId))}/access_tokens`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${createGitHubAppJwt()}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  })

  if (!response.ok) throw new Error(`GitHub App installation token request failed with ${response.status}.`)
  const data = (await response.json()) as { token?: string }
  if (!data.token) throw new Error("GitHub App installation token response did not include a token.")
  return data.token
}

function createGitHubAppJwt() {
  const appId = getGitHubAppId()
  const privateKey = normalizePrivateKey(getGitHubAppPrivateKey())
  if (!appId || !privateKey) throw new Error("GitHub App credentials are missing.")

  const now = Math.floor(Date.now() / 1000)
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }))
  const payload = base64Url(JSON.stringify({ iat: now - 60, exp: now + 9 * 60, iss: appId }))
  const body = `${header}.${payload}`
  const signature = createSign("RSA-SHA256").update(body).sign(privateKey)
  return `${body}.${base64Url(signature)}`
}

function normalizePrivateKey(value: string | undefined) {
  return value?.replace(/\\n/g, "\n")
}

function base64Url(value: string | Buffer) {
  return Buffer.from(value)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "")
}

export { isGitHubAppInstallationConfigured }
