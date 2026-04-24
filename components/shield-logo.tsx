"use client";

import { motion } from "framer-motion";

interface ShieldLogoProps {
  className?: string;
  animate?: boolean;
  size?: "sm" | "md" | "lg";
}

export function ShieldLogo({ className = "", animate = true, size = "md" }: ShieldLogoProps) {
  const sizeClasses = {
    sm: "w-8 h-8",
    md: "w-12 h-12",
    lg: "w-20 h-20",
  };

  return (
    <motion.div
      className={`relative ${sizeClasses[size]} ${className}`}
      initial={animate ? { scale: 0.8, opacity: 0 } : false}
      animate={animate ? { scale: 1, opacity: 1 } : false}
      transition={{ duration: 0.5, ease: "easeOut" }}
    >
      <svg viewBox="0 0 100 100" className="w-full h-full" fill="none">
        <defs>
          <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="oklch(0.75 0.18 165)" />
            <stop offset="100%" stopColor="oklch(0.65 0.15 180)" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        
        {/* Shield body */}
        <motion.path
          d="M50 5 L90 20 L90 45 C90 70 70 90 50 95 C30 90 10 70 10 45 L10 20 Z"
          fill="url(#shieldGradient)"
          filter="url(#glow)"
          initial={animate ? { pathLength: 0 } : { pathLength: 1 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 1, ease: "easeInOut" }}
        />
        
        {/* Inner shield highlight */}
        <path
          d="M50 12 L82 24 L82 45 C82 66 65 82 50 87 C35 82 18 66 18 45 L18 24 Z"
          fill="none"
          stroke="oklch(0.9 0.05 165)"
          strokeWidth="1"
          opacity="0.3"
        />
        
        {/* Checkmark */}
        <motion.path
          d="M35 50 L45 60 L65 40"
          stroke="oklch(0.13 0.015 260)"
          strokeWidth="6"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
          initial={animate ? { pathLength: 0 } : { pathLength: 1 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.5, delay: 0.5, ease: "easeOut" }}
        />
      </svg>
      
      {/* Animated pulse ring */}
      {animate && (
        <motion.div
          className="absolute inset-0 rounded-full border-2 border-primary"
          initial={{ scale: 1, opacity: 0.5 }}
          animate={{ scale: 1.5, opacity: 0 }}
          transition={{ duration: 1.5, repeat: Infinity, ease: "easeOut" }}
        />
      )}
    </motion.div>
  );
}
