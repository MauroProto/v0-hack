"use client";

import { motion } from "framer-motion";
import { LucideIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: { value: number; label: string };
  variant?: "default" | "primary" | "warning" | "destructive" | "success";
  index?: number;
  className?: string;
}

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = "default",
  index = 0,
  className,
}: StatCardProps) {
  const variantStyles = {
    default: {
      iconBg: "bg-secondary",
      iconColor: "text-foreground",
    },
    primary: {
      iconBg: "bg-primary/10",
      iconColor: "text-primary",
    },
    warning: {
      iconBg: "bg-warning/10",
      iconColor: "text-warning",
    },
    destructive: {
      iconBg: "bg-destructive/10",
      iconColor: "text-destructive",
    },
    success: {
      iconBg: "bg-success/10",
      iconColor: "text-success",
    },
  };

  const styles = variantStyles[variant];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.1 }}
    >
      <Card className={cn("bg-card/50 backdrop-blur-sm border-border/50", className)}>
        <CardContent className="p-5">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">{title}</p>
              <p className="text-2xl font-bold font-mono tracking-tight">{value}</p>
              {subtitle && (
                <p className="text-xs text-muted-foreground">{subtitle}</p>
              )}
              {trend && (
                <div className="flex items-center gap-1 text-xs">
                  <span
                    className={cn(
                      "font-medium",
                      trend.value > 0 ? "text-success" : trend.value < 0 ? "text-destructive" : "text-muted-foreground"
                    )}
                  >
                    {trend.value > 0 ? "+" : ""}{trend.value}%
                  </span>
                  <span className="text-muted-foreground">{trend.label}</span>
                </div>
              )}
            </div>
            <div className={cn("p-2.5 rounded-lg", styles.iconBg)}>
              <Icon className={cn("w-5 h-5", styles.iconColor)} />
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
