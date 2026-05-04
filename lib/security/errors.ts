export class SecurityError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
    public readonly headers: Record<string, string> = {},
  ) {
    super(message)
  }
}

export function isSecurityError(error: unknown): error is SecurityError {
  return error instanceof SecurityError
}
