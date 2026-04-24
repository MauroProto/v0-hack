"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileCode,
  GitBranch,
  Download,
  Share2,
  RefreshCw,
  Filter,
  ChevronRight,
  Sparkles,
  ExternalLink,
  TrendingUp,
  TrendingDown,
  Bug,
  Lock,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Navigation } from "@/components/navigation";
import { SecurityScore } from "@/components/security-score";
import { StatCard } from "@/components/stat-card";
import { IssueCard, type SecurityIssue } from "@/components/issue-card";
import { SeverityBadge, type SeverityLevel } from "@/components/severity-badge";
import { cn } from "@/lib/utils";

const mockIssues: SecurityIssue[] = [
  {
    id: "1",
    title: "SQL Injection Vulnerability",
    description: "User input is directly concatenated into SQL query without proper sanitization or parameterization.",
    severity: "critical",
    file: "src/api/users/route.ts",
    line: 45,
    category: "Injection",
    hasAutoFix: true,
  },
  {
    id: "2",
    title: "Hardcoded API Key",
    description: "Sensitive API key is hardcoded in source code. This should be moved to environment variables.",
    severity: "critical",
    file: "src/lib/stripe.ts",
    line: 12,
    category: "Secrets",
    hasAutoFix: true,
  },
  {
    id: "3",
    title: "Missing Rate Limiting",
    description: "API endpoint lacks rate limiting, making it vulnerable to brute force attacks.",
    severity: "high",
    file: "src/api/auth/login/route.ts",
    line: 8,
    category: "Authentication",
    hasAutoFix: true,
  },
  {
    id: "4",
    title: "Cross-Site Scripting (XSS)",
    description: "User-provided content is rendered without proper escaping, allowing potential XSS attacks.",
    severity: "high",
    file: "src/components/Comment.tsx",
    line: 23,
    category: "XSS",
    hasAutoFix: true,
  },
  {
    id: "5",
    title: "Insecure Cookie Configuration",
    description: "Session cookie is missing HttpOnly and Secure flags, making it vulnerable to theft.",
    severity: "medium",
    file: "src/lib/session.ts",
    line: 67,
    category: "Session",
    hasAutoFix: true,
  },
  {
    id: "6",
    title: "Outdated Dependency",
    description: "lodash@4.17.15 has known security vulnerabilities. Update to the latest version.",
    severity: "medium",
    file: "package.json",
    line: 15,
    category: "Dependencies",
    hasAutoFix: true,
  },
  {
    id: "7",
    title: "Missing Input Validation",
    description: "Form inputs are not validated on the server side, allowing malformed data.",
    severity: "low",
    file: "src/api/contact/route.ts",
    line: 34,
    category: "Validation",
    hasAutoFix: false,
  },
  {
    id: "8",
    title: "Verbose Error Messages",
    description: "Error responses include stack traces and internal details that could help attackers.",
    severity: "low",
    file: "src/middleware.ts",
    line: 89,
    category: "Information Disclosure",
    hasAutoFix: true,
  },
];

const categories = [
  { id: "all", label: "All Issues", count: mockIssues.length },
  { id: "critical", label: "Critical", count: mockIssues.filter((i) => i.severity === "critical").length },
  { id: "high", label: "High", count: mockIssues.filter((i) => i.severity === "high").length },
  { id: "medium", label: "Medium", count: mockIssues.filter((i) => i.severity === "medium").length },
  { id: "low", label: "Low", count: mockIssues.filter((i) => i.severity === "low").length },
];

export default function ReportPage() {
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedIssue, setSelectedIssue] = useState<SecurityIssue | null>(null);

  const filteredIssues =
    selectedCategory === "all"
      ? mockIssues
      : mockIssues.filter((i) => i.severity === selectedCategory);

  const securityScore = 72;
  const previousScore = 65;
  const scoreChange = securityScore - previousScore;

  return (
    <div className="min-h-screen bg-background">
      <Navigation />

      <main className="container mx-auto px-4 pt-20 pb-16">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6 mb-8">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold">Security Report</h1>
              <span className="px-2 py-0.5 text-xs font-mono bg-primary/10 text-primary rounded">
                Latest
              </span>
            </div>
            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <FileCode className="w-4 h-4" />
                my-awesome-app
              </span>
              <span className="flex items-center gap-1.5">
                <GitBranch className="w-4 h-4" />
                main
              </span>
              <span className="flex items-center gap-1.5">
                <Clock className="w-4 h-4" />
                2 minutes ago
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" className="gap-2">
              <Download className="w-4 h-4" />
              Export
            </Button>
            <Button variant="outline" size="sm" className="gap-2">
              <Share2 className="w-4 h-4" />
              Share
            </Button>
            <Button size="sm" className="gap-2">
              <RefreshCw className="w-4 h-4" />
              Rescan
            </Button>
          </div>
        </div>

        {/* Score and Stats */}
        <div className="grid lg:grid-cols-4 gap-6 mb-8">
          {/* Main score card */}
          <Card className="lg:col-span-1 bg-card/50 backdrop-blur-sm">
            <CardContent className="p-6 flex flex-col items-center justify-center">
              <SecurityScore score={securityScore} size="lg" />
              <div className="mt-4 flex items-center gap-2">
                {scoreChange > 0 ? (
                  <>
                    <TrendingUp className="w-4 h-4 text-success" />
                    <span className="text-sm text-success font-medium">+{scoreChange} from last scan</span>
                  </>
                ) : scoreChange < 0 ? (
                  <>
                    <TrendingDown className="w-4 h-4 text-destructive" />
                    <span className="text-sm text-destructive font-medium">{scoreChange} from last scan</span>
                  </>
                ) : (
                  <span className="text-sm text-muted-foreground">No change from last scan</span>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Stats */}
          <div className="lg:col-span-3 grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <StatCard
              title="Total Issues"
              value={mockIssues.length}
              subtitle="Across all severity levels"
              icon={Bug}
              variant="default"
              index={0}
            />
            <StatCard
              title="Critical Issues"
              value={mockIssues.filter((i) => i.severity === "critical").length}
              subtitle="Require immediate attention"
              icon={AlertTriangle}
              variant="destructive"
              index={1}
            />
            <StatCard
              title="Auto-fixable"
              value={mockIssues.filter((i) => i.hasAutoFix).length}
              subtitle="Can be fixed automatically"
              icon={Sparkles}
              variant="primary"
              index={2}
            />
          </div>
        </div>

        {/* Category breakdown */}
        <Card className="mb-8 bg-card/50 backdrop-blur-sm">
          <CardHeader className="pb-4">
            <CardTitle className="text-base font-medium">Issue Breakdown by Category</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { icon: Lock, label: "Authentication", count: 2 },
                { icon: Bug, label: "Injection", count: 1 },
                { icon: FileCode, label: "Dependencies", count: 1 },
                { icon: Zap, label: "XSS", count: 1 },
              ].map((cat, i) => (
                <motion.div
                  key={cat.label}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.1 }}
                  className="flex items-center gap-3 p-3 rounded-lg bg-secondary/50"
                >
                  <div className="p-2 rounded-lg bg-background">
                    <cat.icon className="w-4 h-4 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">{cat.label}</p>
                    <p className="text-xs text-muted-foreground">{cat.count} issues</p>
                  </div>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Issues List */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Security Issues</h2>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="gap-2">
                <Filter className="w-4 h-4" />
                Filter
              </Button>
            </div>
          </div>

          {/* Category tabs */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2">
            {categories.map((cat) => (
              <button
                key={cat.id}
                onClick={() => setSelectedCategory(cat.id)}
                className={cn(
                  "flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium transition-colors whitespace-nowrap",
                  selectedCategory === cat.id
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-muted-foreground hover:text-foreground"
                )}
              >
                {cat.label}
                <span
                  className={cn(
                    "px-1.5 py-0.5 text-xs rounded-full",
                    selectedCategory === cat.id
                      ? "bg-primary-foreground/20 text-primary-foreground"
                      : "bg-muted text-muted-foreground"
                  )}
                >
                  {cat.count}
                </span>
              </button>
            ))}
          </div>

          {/* Issues grid */}
          <div className="space-y-3">
            {filteredIssues.map((issue, index) => (
              <IssueCard
                key={issue.id}
                issue={issue}
                index={index}
                onViewDetails={(i) => setSelectedIssue(i)}
                onAutoFix={(i) => console.log("Auto-fix", i)}
              />
            ))}
          </div>

          {filteredIssues.length === 0 && (
            <div className="text-center py-12">
              <CheckCircle2 className="w-12 h-12 text-success mx-auto mb-4" />
              <p className="text-lg font-medium">No issues in this category</p>
              <p className="text-muted-foreground">Great job keeping your code secure!</p>
            </div>
          )}
        </div>

        {/* Quick Actions */}
        <div className="mt-12 grid sm:grid-cols-2 gap-4">
          <Card className="bg-card/50 backdrop-blur-sm hover:border-primary/30 transition-colors cursor-pointer">
            <CardContent className="p-6 flex items-center gap-4">
              <div className="p-3 rounded-lg bg-primary/10">
                <Sparkles className="w-6 h-6 text-primary" />
              </div>
              <div className="flex-1">
                <h3 className="font-semibold">Auto-fix All Issues</h3>
                <p className="text-sm text-muted-foreground">
                  Apply AI-suggested fixes to {mockIssues.filter((i) => i.hasAutoFix).length} issues
                </p>
              </div>
              <ChevronRight className="w-5 h-5 text-muted-foreground" />
            </CardContent>
          </Card>

          <Link href="/issues">
            <Card className="bg-card/50 backdrop-blur-sm hover:border-primary/30 transition-colors cursor-pointer h-full">
              <CardContent className="p-6 flex items-center gap-4 h-full">
                <div className="p-3 rounded-lg bg-secondary">
                  <AlertTriangle className="w-6 h-6 text-muted-foreground" />
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold">View All Issues</h3>
                  <p className="text-sm text-muted-foreground">
                    Detailed view with code previews and fix suggestions
                  </p>
                </div>
                <ChevronRight className="w-5 h-5 text-muted-foreground" />
              </CardContent>
            </Card>
          </Link>
        </div>
      </main>
    </div>
  );
}
