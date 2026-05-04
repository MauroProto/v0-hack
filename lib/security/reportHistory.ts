import type { RequestIdentity } from "./request"

export function reportHistoryOwnerHash(identity: RequestIdentity) {
  return identity.subjectHash
}
