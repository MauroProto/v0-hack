import "server-only"

import { createAnthropic, type AnthropicLanguageModelOptions } from "@ai-sdk/anthropic"
import { createDeepSeek, type DeepSeekLanguageModelOptions } from "@ai-sdk/deepseek"
import type { LanguageModel } from "ai"
import { badgerEnv } from "@/lib/config/env"

type ScanReviewMode = "rules" | "normal" | "max"

type AiProvider = "gateway" | "anthropic" | "deepseek"

export interface ResolvedAiModel {
  configured: true
  provider: AiProvider
  modelId: string
  model: LanguageModel
  reasoningEffort?: string
  providerOptions?: {
    anthropic?: AnthropicLanguageModelOptions
    deepseek?: DeepSeekLanguageModelOptions
  }
}

export interface AiModelStatus {
  configured: boolean
  provider?: AiProvider
  modelId?: string
  reason?: string
}

const DEFAULT_GATEWAY_MODEL = "openai/gpt-5.2-mini"
const DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-7"
const DEFAULT_DEEPSEEK_MODEL = "deepseek-v4-pro"
const DEFAULT_DEEPSEEK_REASONING_EFFORT = "high"
const DEFAULT_ANTHROPIC_EFFORT = "xhigh"
const DEFAULT_ANTHROPIC_NORMAL_EFFORT = "low"
const DEFAULT_ANTHROPIC_MAX_EFFORT = "max"

export function resolveAiModel(): ResolvedAiModel | null {
  const requestedProvider = normalizeProvider(badgerEnv("AI_PROVIDER"))

  if (requestedProvider === "anthropic") return resolveAnthropicModel()
  if (requestedProvider === "deepseek") return resolveDeepSeekModel()
  if (requestedProvider === "gateway") return resolveGatewayModel()

  return resolveGatewayModel() ?? resolveAnthropicModel() ?? resolveDeepSeekModel()
}

export function resolvePullRequestReviewModel(): ResolvedAiModel | null {
  return resolveAnthropicModel({
    modelId: badgerEnv("PR_REVIEW_MODEL") || badgerEnv("ANTHROPIC_MODEL") || DEFAULT_ANTHROPIC_MODEL,
    effort: readAnthropicEffort(badgerEnv("PR_REVIEW_EFFORT"), "max"),
  })
}

export function resolveScanReviewModel(mode: ScanReviewMode): ResolvedAiModel | null {
  const isMax = mode === "max"
  const effort = isMax
    ? readAnthropicEffort(badgerEnv("ANTHROPIC_MAX_EFFORT"), DEFAULT_ANTHROPIC_MAX_EFFORT)
    : readAnthropicEffort(badgerEnv("ANTHROPIC_NORMAL_EFFORT"), DEFAULT_ANTHROPIC_NORMAL_EFFORT)

  return resolveAnthropicModel({
    modelId: badgerEnv("SCAN_REVIEW_MODEL") || badgerEnv("ANTHROPIC_MODEL") || DEFAULT_ANTHROPIC_MODEL,
    effort,
  })
}

export function getAiModelStatus(): AiModelStatus {
  const model = resolveAiModel()
  if (model) {
    return {
      configured: true,
      provider: model.provider,
      modelId: model.modelId,
    }
  }

  return {
    configured: false,
    reason: "No server-side AI provider credentials configured.",
  }
}

function resolveGatewayModel(): ResolvedAiModel | null {
  if (!process.env.AI_GATEWAY_API_KEY && !process.env.VERCEL_OIDC_TOKEN) return null

  const modelId = badgerEnv("MODEL") || DEFAULT_GATEWAY_MODEL
  return {
    configured: true,
    provider: "gateway",
    modelId,
    model: modelId,
  }
}

function resolveAnthropicModel(options?: { modelId?: string; effort?: AnthropicLanguageModelOptions["effort"] }): ResolvedAiModel | null {
  const apiKey = process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY
  if (!apiKey) return null

  const modelId = options?.modelId || badgerEnv("ANTHROPIC_MODEL") || badgerEnv("CLAUDE_MODEL") || DEFAULT_ANTHROPIC_MODEL
  const effort = options?.effort ?? readAnthropicEffort(badgerEnv("ANTHROPIC_EFFORT"), DEFAULT_ANTHROPIC_EFFORT)
  const anthropic = createAnthropic({ apiKey })
  return {
    configured: true,
    provider: "anthropic",
    modelId,
    model: anthropic(modelId),
    reasoningEffort: effort,
    providerOptions: {
      anthropic: {
        thinking: { type: "adaptive" },
        effort,
      } satisfies AnthropicLanguageModelOptions,
    },
  }
}

function resolveDeepSeekModel(): ResolvedAiModel | null {
  const apiKey = process.env.DEEPSEEK_API_KEY
  if (!apiKey) return null

  const modelId = badgerEnv("DEEPSEEK_MODEL") || DEFAULT_DEEPSEEK_MODEL
  const deepseek = createDeepSeek({
    apiKey,
    fetch: withDeepSeekReasoningEffort(fetch),
  })
  return {
    configured: true,
    provider: "deepseek",
    modelId,
    model: deepseek(modelId),
    providerOptions: {
      deepseek: {
        thinking: { type: "enabled" },
      } satisfies DeepSeekLanguageModelOptions,
    },
  }
}

function normalizeProvider(value: string | undefined): AiProvider | null {
  const normalized = value?.trim().toLowerCase()
  if (!normalized) return null
  if (normalized === "claude") return "anthropic"
  if (normalized === "anthropic" || normalized === "deepseek" || normalized === "gateway") return normalized
  return null
}

function withDeepSeekReasoningEffort(fetchImpl: typeof fetch): typeof fetch {
  return async (input, init) => {
    if (typeof init?.body !== "string") return fetchImpl(input, init)

    try {
      const payload = JSON.parse(init.body) as Record<string, unknown>
      if (!("reasoning_effort" in payload)) {
        payload.reasoning_effort = readDeepSeekReasoningEffort()
      }

      return fetchImpl(input, {
        ...init,
        body: JSON.stringify(payload),
      })
    } catch {
      return fetchImpl(input, init)
    }
  }
}

function readDeepSeekReasoningEffort() {
  const value = badgerEnv("DEEPSEEK_REASONING_EFFORT")?.toLowerCase()
  if (value === "low" || value === "medium" || value === "high") return value
  return DEFAULT_DEEPSEEK_REASONING_EFFORT
}

function readAnthropicEffort(rawValue: string | undefined, fallback: AnthropicLanguageModelOptions["effort"]) {
  const value = rawValue?.trim().toLowerCase()
  if (value === "low" || value === "medium" || value === "high" || value === "xhigh" || value === "max") return value
  return fallback
}
