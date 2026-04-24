"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  X,
  Sparkles,
  ChevronRight,
  ChevronLeft,
  FileCode,
  ExternalLink,
  Copy,
  Check,
  ArrowRight,
  Filter,
  Search,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Navigation } from "@/components/navigation";
import { SeverityBadge, type SeverityLevel } from "@/components/severity-badge";
import { CodePreview } from "@/components/code-preview";
import { cn } from "@/lib/utils";

interface SecurityIssue {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  file: string;
  line: number;
  category: string;
  hasAutoFix: boolean;
  explanation?: string;
  originalCode?: { number: number; content: string; highlight?: "error" }[];
  fixedCode?: { number: number; content: string; isNew?: boolean; isRemoved?: boolean }[];
}

const mockIssues: SecurityIssue[] = [
  {
    id: "1",
    title: "SQL Injection Vulnerability",
    description: "User input is directly concatenated into SQL query without proper sanitization.",
    severity: "critical",
    file: "src/api/users/route.ts",
    line: 45,
    category: "Injection",
    hasAutoFix: true,
    explanation: "This vulnerability allows attackers to execute arbitrary SQL commands. The user input should be parameterized using prepared statements instead of string concatenation.",
    originalCode: [
      { number: 43, content: "export async function GET(request: Request) {" },
      { number: 44, content: "  const { searchParams } = new URL(request.url);" },
      { number: 45, content: "  const userId = searchParams.get('id');", highlight: "error" },
      { number: 46, content: "  const query = `SELECT * FROM users WHERE id = ${userId}`;", highlight: "error" },
      { number: 47, content: "  const result = await db.execute(query);", highlight: "error" },
      { number: 48, content: "  return Response.json(result);" },
      { number: 49, content: "}" },
    ],
    fixedCode: [
      { number: 43, content: "export async function GET(request: Request) {" },
      { number: 44, content: "  const { searchParams } = new URL(request.url);" },
      { number: 45, content: "  const userId = searchParams.get('id');", isRemoved: true },
      { number: 45, content: "  const userId = parseInt(searchParams.get('id') || '0', 10);", isNew: true },
      { number: 46, content: "  const query = `SELECT * FROM users WHERE id = ${userId}`;", isRemoved: true },
      { number: 46, content: "  const query = 'SELECT * FROM users WHERE id = $1';", isNew: true },
      { number: 47, content: "  const result = await db.execute(query);", isRemoved: true },
      { number: 47, content: "  const result = await db.execute(query, [userId]);", isNew: true },
      { number: 48, content: "  return Response.json(result);" },
      { number: 49, content: "}" },
    ],
  },
  {
    id: "2",
    title: "Hardcoded API Key",
    description: "Sensitive API key is hardcoded in source code.",
    severity: "critical",
    file: "src/lib/stripe.ts",
    line: 12,
    category: "Secrets",
    hasAutoFix: true,
    explanation: "Hardcoded secrets can be exposed in version control and build artifacts. Use environment variables to store sensitive information.",
    originalCode: [
      { number: 10, content: "import Stripe from 'stripe';" },
      { number: 11, content: "" },
      { number: 12, content: "const stripe = new Stripe('sk_live_abc123xyz789');", highlight: "error" },
      { number: 13, content: "" },
      { number: 14, content: "export default stripe;" },
    ],
    fixedCode: [
      { number: 10, content: "import Stripe from 'stripe';" },
      { number: 11, content: "" },
      { number: 12, content: "const stripe = new Stripe('sk_live_abc123xyz789');", isRemoved: true },
      { number: 12, content: "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);", isNew: true },
      { number: 13, content: "" },
      { number: 14, content: "export default stripe;" },
    ],
  },
  {
    id: "3",
    title: "Missing Rate Limiting",
    description: "API endpoint lacks rate limiting, vulnerable to brute force attacks.",
    severity: "high",
    file: "src/api/auth/login/route.ts",
    line: 8,
    category: "Authentication",
    hasAutoFix: true,
    explanation: "Without rate limiting, attackers can make unlimited login attempts to guess passwords. Implement rate limiting to restrict the number of requests per IP.",
    originalCode: [
      { number: 6, content: "import { db } from '@/lib/db';" },
      { number: 7, content: "" },
      { number: 8, content: "export async function POST(request: Request) {", highlight: "error" },
      { number: 9, content: "  const { email, password } = await request.json();" },
      { number: 10, content: "  const user = await db.user.findUnique({ where: { email } });" },
    ],
    fixedCode: [
      { number: 6, content: "import { db } from '@/lib/db';" },
      { number: 7, content: "import { rateLimit } from '@/lib/rate-limit';", isNew: true },
      { number: 8, content: "" },
      { number: 9, content: "export async function POST(request: Request) {" },
      { number: 10, content: "  const ip = request.headers.get('x-forwarded-for') || 'unknown';", isNew: true },
      { number: 11, content: "  const { success } = await rateLimit(ip, { limit: 5, window: 60 });", isNew: true },
      { number: 12, content: "  if (!success) return new Response('Too many requests', { status: 429 });", isNew: true },
      { number: 13, content: "" },
      { number: 14, content: "  const { email, password } = await request.json();" },
      { number: 15, content: "  const user = await db.user.findUnique({ where: { email } });" },
    ],
  },
];

export default function IssuesPage() {
  const [selectedIssue, setSelectedIssue] = useState<SecurityIssue | null>(mockIssues[0]);
  const [fixingIssue, setFixingIssue] = useState<string | null>(null);
  const [fixedIssues, setFixedIssues] = useState<Set<string>>(new Set());
  const [showDiff, setShowDiff] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [copied, setCopied] = useState(false);

  const handleAutoFix = async (issueId: string) => {
    setFixingIssue(issueId);
    await new Promise((r) => setTimeout(r, 2000));
    setFixedIssues((prev) => new Set([...prev, issueId]));
    setFixingIssue(null);
  };

  const handleCopyCode = () => {
    if (selectedIssue?.fixedCode) {
      const code = selectedIssue.fixedCode
        .filter((l) => !l.isRemoved)
        .map((l) => l.content)
        .join("\n");
      navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const filteredIssues = mockIssues.filter(
    (issue) =>
      issue.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      issue.file.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const currentIndex = selectedIssue ? filteredIssues.findIndex((i) => i.id === selectedIssue.id) : -1;

  const goToNextIssue = () => {
    if (currentIndex < filteredIssues.length - 1) {
      setSelectedIssue(filteredIssues[currentIndex + 1]);
    }
  };

  const goToPrevIssue = () => {
    if (currentIndex > 0) {
      setSelectedIssue(filteredIssues[currentIndex - 1]);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Navigation />

      <main className="pt-14">
        <div className="flex h-[calc(100vh-3.5rem)]">
          {/* Issues sidebar */}
          <div className="w-80 border-r border-border flex flex-col bg-card/30">
            <div className="p-4 border-b border-border space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="font-semibold">Issues</h2>
                <span className="text-sm text-muted-foreground">
                  {filteredIssues.length} total
                </span>
              </div>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search issues..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 h-9"
                />
              </div>
            </div>

            <div className="flex-1 overflow-y-auto">
              {filteredIssues.map((issue) => (
                <button
                  key={issue.id}
                  onClick={() => setSelectedIssue(issue)}
                  className={cn(
                    "w-full p-4 text-left border-b border-border/50 transition-colors",
                    selectedIssue?.id === issue.id
                      ? "bg-primary/5 border-l-2 border-l-primary"
                      : "hover:bg-secondary/50"
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div
                      className={cn(
                        "mt-0.5 p-1.5 rounded",
                        fixedIssues.has(issue.id)
                          ? "bg-success/10 text-success"
                          : issue.severity === "critical"
                          ? "bg-destructive/10 text-destructive"
                          : issue.severity === "high"
                          ? "bg-destructive/10 text-destructive/80"
                          : "bg-warning/10 text-warning"
                      )}
                    >
                      {fixedIssues.has(issue.id) ? (
                        <CheckCircle2 className="w-4 h-4" />
                      ) : (
                        <AlertTriangle className="w-4 h-4" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p
                        className={cn(
                          "font-medium text-sm truncate",
                          fixedIssues.has(issue.id) && "line-through text-muted-foreground"
                        )}
                      >
                        {issue.title}
                      </p>
                      <p className="text-xs text-muted-foreground truncate font-mono mt-0.5">
                        {issue.file}:{issue.line}
                      </p>
                      <div className="flex items-center gap-2 mt-1.5">
                        <SeverityBadge severity={issue.severity} showDot={false} />
                        {issue.hasAutoFix && !fixedIssues.has(issue.id) && (
                          <span className="text-xs text-primary">Auto-fix</span>
                        )}
                      </div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Issue detail */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {selectedIssue ? (
              <>
                {/* Issue header */}
                <div className="p-6 border-b border-border bg-card/30">
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-2">
                      <div className="flex items-center gap-3">
                        <SeverityBadge severity={selectedIssue.severity} />
                        <span className="text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded">
                          {selectedIssue.category}
                        </span>
                        {fixedIssues.has(selectedIssue.id) && (
                          <span className="text-xs text-success bg-success/10 px-2 py-0.5 rounded flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3" />
                            Fixed
                          </span>
                        )}
                      </div>
                      <h1 className="text-xl font-bold">{selectedIssue.title}</h1>
                      <p className="text-muted-foreground">{selectedIssue.description}</p>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={goToPrevIssue}
                        disabled={currentIndex <= 0}
                      >
                        <ChevronLeft className="w-4 h-4" />
                      </Button>
                      <span className="text-sm text-muted-foreground min-w-[60px] text-center">
                        {currentIndex + 1} / {filteredIssues.length}
                      </span>
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={goToNextIssue}
                        disabled={currentIndex >= filteredIssues.length - 1}
                      >
                        <ChevronRight className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>

                  {/* File location */}
                  <div className="flex items-center gap-4 mt-4 p-3 rounded-lg bg-secondary/50">
                    <FileCode className="w-4 h-4 text-muted-foreground" />
                    <span className="text-sm font-mono flex-1">
                      {selectedIssue.file}
                      <span className="text-primary">:{selectedIssue.line}</span>
                    </span>
                    <Button variant="ghost" size="sm" className="gap-1.5 text-xs">
                      <ExternalLink className="w-3 h-3" />
                      Open in Editor
                    </Button>
                  </div>
                </div>

                {/* Issue content */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6">
                  {/* Explanation */}
                  {selectedIssue.explanation && (
                    <Card className="bg-card/50">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                          <Sparkles className="w-4 h-4 text-primary" />
                          AI Analysis
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <p className="text-sm text-muted-foreground">
                          {selectedIssue.explanation}
                        </p>
                      </CardContent>
                    </Card>
                  )}

                  {/* Code preview */}
                  {selectedIssue.originalCode && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-medium">
                          {showDiff ? "Suggested Fix" : "Original Code"}
                        </h3>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setShowDiff(!showDiff)}
                            className="text-xs"
                          >
                            {showDiff ? "Show Original" : "Show Diff"}
                          </Button>
                          {showDiff && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={handleCopyCode}
                              className="text-xs gap-1.5"
                            >
                              {copied ? (
                                <>
                                  <Check className="w-3 h-3" />
                                  Copied
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  Copy Fix
                                </>
                              )}
                            </Button>
                          )}
                        </div>
                      </div>

                      <CodePreview
                        filename={selectedIssue.file}
                        lines={
                          showDiff && selectedIssue.fixedCode
                            ? selectedIssue.fixedCode
                            : selectedIssue.originalCode
                        }
                      />
                    </div>
                  )}

                  {/* Actions */}
                  {selectedIssue.hasAutoFix && !fixedIssues.has(selectedIssue.id) && (
                    <div className="flex items-center gap-3 pt-4">
                      <Button
                        size="lg"
                        className="glow-primary gap-2"
                        onClick={() => handleAutoFix(selectedIssue.id)}
                        disabled={fixingIssue === selectedIssue.id}
                      >
                        {fixingIssue === selectedIssue.id ? (
                          <>
                            <Loader2 className="w-4 h-4 animate-spin" />
                            Applying Fix...
                          </>
                        ) : (
                          <>
                            <Sparkles className="w-4 h-4" />
                            Apply Auto-fix
                          </>
                        )}
                      </Button>
                      <Button variant="outline" size="lg">
                        Dismiss Issue
                      </Button>
                    </div>
                  )}

                  {fixedIssues.has(selectedIssue.id) && (
                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="flex items-center gap-3 p-4 rounded-lg bg-success/10 border border-success/30"
                    >
                      <CheckCircle2 className="w-5 h-5 text-success" />
                      <div>
                        <p className="font-medium text-success">Issue Fixed</p>
                        <p className="text-sm text-muted-foreground">
                          The fix has been applied to your codebase.
                        </p>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="ml-auto text-success hover:text-success"
                        onClick={goToNextIssue}
                      >
                        Next Issue
                        <ArrowRight className="w-4 h-4 ml-1" />
                      </Button>
                    </motion.div>
                  )}
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center">
                <div className="text-center">
                  <AlertTriangle className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-lg font-medium">Select an issue</p>
                  <p className="text-muted-foreground">
                    Choose an issue from the sidebar to view details
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
