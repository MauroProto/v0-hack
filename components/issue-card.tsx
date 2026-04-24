"use client";

import { motion } from "framer-motion";
import { AlertTriangle, FileCode, ChevronRight, Sparkles } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge, type SeverityLevel } from "@/components/severity-badge";
import { cn } from "@/lib/utils";

export interface SecurityIssue {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  file: string;
  line: number;
  category: string;
  hasAutoFix?: boolean;
}

interface IssueCardProps {
  issue: SecurityIssue;
  index?: number;
  onViewDetails?: (issue: SecurityIssue) => void;
  onAutoFix?: (issue: SecurityIssue) => void;
  className?: string;
}

export function IssueCard({ issue, index = 0, onViewDetails, onAutoFix, className }: IssueCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.05 }}
    >
      <Card
        className={cn(
          "group relative overflow-hidden transition-all duration-300",
          "hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5",
          "bg-card/50 backdrop-blur-sm",
          className
        )}
      >
        {/* Severity indicator bar */}
        <div
          className={cn(
            "absolute left-0 top-0 bottom-0 w-1",
            issue.severity === "critical" && "bg-destructive",
            issue.severity === "high" && "bg-destructive/80",
            issue.severity === "medium" && "bg-warning",
            issue.severity === "low" && "bg-info",
            issue.severity === "info" && "bg-muted-foreground"
          )}
        />
        
        <CardContent className="p-4 pl-5">
          <div className="flex items-start gap-4">
            {/* Icon */}
            <div
              className={cn(
                "flex-shrink-0 p-2 rounded-lg",
                issue.severity === "critical" && "bg-destructive/10 text-destructive",
                issue.severity === "high" && "bg-destructive/10 text-destructive/80",
                issue.severity === "medium" && "bg-warning/10 text-warning",
                issue.severity === "low" && "bg-info/10 text-info",
                issue.severity === "info" && "bg-muted text-muted-foreground"
              )}
            >
              <AlertTriangle className="w-5 h-5" />
            </div>
            
            {/* Content */}
            <div className="flex-1 min-w-0 space-y-2">
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1">
                  <h3 className="font-semibold text-foreground leading-tight">
                    {issue.title}
                  </h3>
                  <p className="text-sm text-muted-foreground line-clamp-2">
                    {issue.description}
                  </p>
                </div>
                <SeverityBadge severity={issue.severity} />
              </div>
              
              {/* File location */}
              <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
                <FileCode className="w-3.5 h-3.5" />
                <span className="truncate">{issue.file}</span>
                <span className="text-primary">:{issue.line}</span>
              </div>
              
              {/* Actions */}
              <div className="flex items-center gap-2 pt-1">
                {issue.hasAutoFix && onAutoFix && (
                  <Button
                    variant="secondary"
                    size="sm"
                    className="h-7 text-xs gap-1.5 bg-primary/10 text-primary hover:bg-primary/20"
                    onClick={() => onAutoFix(issue)}
                  >
                    <Sparkles className="w-3 h-3" />
                    Auto-fix
                  </Button>
                )}
                {onViewDetails && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground"
                    onClick={() => onViewDetails(issue)}
                  >
                    View Details
                    <ChevronRight className="w-3 h-3" />
                  </Button>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
