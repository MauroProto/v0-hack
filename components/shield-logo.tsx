"use client"

import { motion } from "framer-motion"

interface ShieldLogoProps {
  className?: string
  animate?: boolean
  size?: "sm" | "md" | "lg" | "xl"
  variant?: "default" | "filled"
}

export function ShieldLogo({ className = "", animate = true, size = "md", variant = "default" }: ShieldLogoProps) {
  const sizeClasses = {
    sm: "w-7 h-7",
    md: "w-10 h-10",
    lg: "w-16 h-16",
    xl: "w-32 h-32",
  }

  const strokeWidth = size === "sm" ? 6 : size === "md" ? 5 : 4

  return (
    <motion.div
      className={`relative ${sizeClasses[size]} ${className}`}
      initial={animate ? { scale: 0.9, opacity: 0 } : false}
      animate={animate ? { scale: 1, opacity: 1 } : false}
      transition={{ duration: 0.5, ease: "easeOut" }}
      aria-hidden="true"
    >
      <svg viewBox="-120 -130 240 320" className="w-full h-full" fill="none">
        {/* Shield outline */}
        <motion.path
          d="M0 -120 L110 -85 L110 20 C110 95 55 160 0 180 C-55 160 -110 95 -110 20 L-110 -85 Z"
          fill={variant === "filled" ? "var(--color-foreground)" : "none"}
          stroke="var(--color-foreground)"
          strokeWidth={strokeWidth}
          strokeLinejoin="round"
          initial={animate ? { pathLength: 0 } : { pathLength: 1 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 1, ease: "easeInOut" }}
        />

        {/* Checkmark */}
        <motion.path
          d="M-35 10 L-10 35 L40 -25"
          stroke="var(--color-primary)"
          strokeWidth={strokeWidth + 2}
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
          initial={animate ? { pathLength: 0 } : { pathLength: 1 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.6, delay: 0.5, ease: "easeOut" }}
        />
      </svg>
    </motion.div>
  )
}
