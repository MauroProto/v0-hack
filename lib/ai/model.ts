import "server-only"

import { createAnthropic } from "@ai-sdk/anthropic"
import { createDeepSeek, type DeepSeekLanguageModelOptions } from "@ai-sdk/deepseek"
import type { LanguageModel } from "ai"

type AiProvider = "gateway" | "anthropic" | "deepseek"

export interface ResolvedAiModel {
  configured: true
  provider: AiProvider
  modelId: string
  model: LanguageModel
  providerOptions?: {
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
const DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"
const DEFAULT_DEEPSEEK_MODEL = "deepseek-v4-pro"

export function resolveAiModel(): ResolvedAiModel | null {
  const requestedProvider = normalizeProvider(process.env.VIBESHIELD_AI_PROVIDER)

  if (requestedProvider === "anthropic") return resolveAnthropicModel()
  if (requestedProvider === "deepseek") return resolveDeepSeekModel()
  if (requestedProvider === "gateway") return resolveGatewayModel()

  return resolveGatewayModel() ?? resolveAnthropicModel() ?? resolveDeepSeekModel()
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

  const modelId = process.env.VIBESHIELD_MODEL || DEFAULT_GATEWAY_MODEL
  return {
    configured: true,
    provider: "gateway",
    modelId,
    model: modelId,
  }
}

function resolveAnthropicModel(): ResolvedAiModel | null {
  const apiKey = process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY
  if (!apiKey) return null

  const modelId = process.env.VIBESHIELD_ANTHROPIC_MODEL || process.env.VIBESHIELD_CLAUDE_MODEL || DEFAULT_ANTHROPIC_MODEL
  const anthropic = createAnthropic({ apiKey })
  return {
    configured: true,
    provider: "anthropic",
    modelId,
    model: anthropic(modelId),
  }
}

function resolveDeepSeekModel(): ResolvedAiModel | null {
  const apiKey = process.env.DEEPSEEK_API_KEY
  if (!apiKey) return null

  const modelId = process.env.VIBESHIELD_DEEPSEEK_MODEL || DEFAULT_DEEPSEEK_MODEL
  const deepseek = createDeepSeek({ apiKey })
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
