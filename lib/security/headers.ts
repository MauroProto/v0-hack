export const API_SECURITY_HEADERS = {
  "Cache-Control": "no-store, max-age=0",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
}

export function apiHeaders(headers?: HeadersInit) {
  return {
    ...API_SECURITY_HEADERS,
    ...headers,
  }
}
