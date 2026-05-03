export function isGitHubAppConfigured() {
  return Boolean(getGitHubAppId() && getGitHubAppPrivateKey())
}

export function isGitHubAppInstallationConfigured() {
  return Boolean(isGitHubAppConfigured() && getGitHubAppInstallationId())
}

export function getGitHubAppId() {
  return process.env.BADGER_GITHUB_APP_ID?.trim() || process.env.GITHUB_APP_ID?.trim()
}

export function getGitHubAppPrivateKey() {
  return process.env.BADGER_GITHUB_APP_PRIVATE_KEY?.trim() || process.env.GITHUB_APP_PRIVATE_KEY?.trim()
}

export function getGitHubAppInstallationId() {
  return process.env.BADGER_GITHUB_APP_INSTALLATION_ID?.trim() || process.env.GITHUB_APP_INSTALLATION_ID?.trim()
}

export function getGitHubAppClientId() {
  return process.env.BADGER_GITHUB_APP_CLIENT_ID?.trim() || process.env.GITHUB_APP_CLIENT_ID?.trim()
}

export function getGitHubAppClientSecret() {
  return process.env.BADGER_GITHUB_APP_CLIENT_SECRET?.trim() || process.env.GITHUB_APP_CLIENT_SECRET?.trim()
}
