"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  User,
  Bell,
  Shield,
  Key,
  Github,
  GitBranch,
  Webhook,
  Calendar,
  Clock,
  ChevronRight,
  Check,
  ExternalLink,
  Plus,
  Trash2,
  Settings2,
  Mail,
  Slack,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Navigation } from "@/components/navigation";
import { cn } from "@/lib/utils";

const tabs = [
  { id: "general", label: "General", icon: Settings2 },
  { id: "integrations", label: "Integrations", icon: Github },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "scanning", label: "Scanning", icon: Shield },
  { id: "api", label: "API Keys", icon: Key },
];

const connectedRepos = [
  { name: "my-awesome-app", provider: "github", branch: "main", lastScan: "2 hours ago" },
  { name: "next-saas-starter", provider: "github", branch: "develop", lastScan: "1 day ago" },
  { name: "api-gateway", provider: "gitlab", branch: "main", lastScan: "3 days ago" },
];

const scanSchedules = [
  { repo: "my-awesome-app", frequency: "Daily", time: "02:00 UTC", active: true },
  { repo: "next-saas-starter", frequency: "Weekly", time: "Sundays 00:00 UTC", active: true },
  { repo: "api-gateway", frequency: "On Push", time: "Triggered by commits", active: false },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("general");
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [notifySlack, setNotifySlack] = useState(false);
  const [notifyCritical, setNotifyCritical] = useState(true);
  const [notifyWeekly, setNotifyWeekly] = useState(true);

  return (
    <div className="min-h-screen bg-background">
      <Navigation />

      <main className="container mx-auto px-4 pt-20 pb-16">
        <div className="max-w-4xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-2xl font-bold mb-1">Settings</h1>
            <p className="text-muted-foreground">
              Manage your account, integrations, and scanning preferences
            </p>
          </div>

          <div className="flex flex-col md:flex-row gap-8">
            {/* Sidebar tabs */}
            <div className="md:w-48 flex-shrink-0">
              <nav className="space-y-1">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={cn(
                      "w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg transition-colors text-left",
                      activeTab === tab.id
                        ? "bg-primary/10 text-primary"
                        : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                    )}
                  >
                    <tab.icon className="w-4 h-4" />
                    {tab.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Content */}
            <div className="flex-1 space-y-6">
              {activeTab === "general" && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-6"
                >
                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">Profile</CardTitle>
                      <CardDescription>Your account information</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex items-center gap-4">
                        <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                          <User className="w-8 h-8 text-primary" />
                        </div>
                        <div>
                          <p className="font-medium">John Developer</p>
                          <p className="text-sm text-muted-foreground">john@example.com</p>
                        </div>
                        <Button variant="outline" size="sm" className="ml-auto">
                          Edit Profile
                        </Button>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">Preferences</CardTitle>
                      <CardDescription>Customize your experience</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">Dark Mode</p>
                          <p className="text-xs text-muted-foreground">Use dark theme</p>
                        </div>
                        <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-primary/10 text-primary text-sm">
                          <Check className="w-4 h-4" />
                          Enabled
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">Timezone</p>
                          <p className="text-xs text-muted-foreground">For scheduled scans</p>
                        </div>
                        <Button variant="outline" size="sm">
                          UTC (GMT+0)
                          <ChevronRight className="w-4 h-4 ml-1" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}

              {activeTab === "integrations" && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-6"
                >
                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">Connected Repositories</CardTitle>
                      <CardDescription>Manage your connected Git repositories</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {connectedRepos.map((repo) => (
                        <div
                          key={repo.name}
                          className="flex items-center gap-4 p-3 rounded-lg bg-secondary/50"
                        >
                          <Github className="w-5 h-5 text-muted-foreground" />
                          <div className="flex-1">
                            <p className="font-medium text-sm">{repo.name}</p>
                            <div className="flex items-center gap-3 text-xs text-muted-foreground">
                              <span className="flex items-center gap-1">
                                <GitBranch className="w-3 h-3" />
                                {repo.branch}
                              </span>
                              <span>Last scan: {repo.lastScan}</span>
                            </div>
                          </div>
                          <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-destructive">
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      ))}
                      <Button variant="outline" className="w-full gap-2">
                        <Plus className="w-4 h-4" />
                        Connect Repository
                      </Button>
                    </CardContent>
                  </Card>

                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">Webhooks</CardTitle>
                      <CardDescription>Configure webhook integrations</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center gap-4 p-4 rounded-lg border border-dashed border-border">
                        <Webhook className="w-8 h-8 text-muted-foreground" />
                        <div className="flex-1">
                          <p className="font-medium text-sm">No webhooks configured</p>
                          <p className="text-xs text-muted-foreground">
                            Set up webhooks to receive scan results
                          </p>
                        </div>
                        <Button variant="outline" size="sm">
                          Add Webhook
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}

              {activeTab === "notifications" && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-6"
                >
                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">Notification Channels</CardTitle>
                      <CardDescription>How you want to be notified</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex items-center justify-between p-3 rounded-lg bg-secondary/50">
                        <div className="flex items-center gap-3">
                          <Mail className="w-5 h-5 text-muted-foreground" />
                          <div>
                            <p className="font-medium text-sm">Email</p>
                            <p className="text-xs text-muted-foreground">john@example.com</p>
                          </div>
                        </div>
                        <button
                          onClick={() => setNotifyEmail(!notifyEmail)}
                          className={cn(
                            "w-10 h-6 rounded-full transition-colors relative",
                            notifyEmail ? "bg-primary" : "bg-muted"
                          )}
                        >
                          <span
                            className={cn(
                              "absolute top-1 w-4 h-4 rounded-full bg-white transition-transform",
                              notifyEmail ? "translate-x-5" : "translate-x-1"
                            )}
                          />
                        </button>
                      </div>

                      <div className="flex items-center justify-between p-3 rounded-lg bg-secondary/50">
                        <div className="flex items-center gap-3">
                          <Slack className="w-5 h-5 text-muted-foreground" />
                          <div>
                            <p className="font-medium text-sm">Slack</p>
                            <p className="text-xs text-muted-foreground">Not connected</p>
                          </div>
                        </div>
                        <Button variant="outline" size="sm">
                          Connect
                        </Button>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">Notification Preferences</CardTitle>
                      <CardDescription>What you want to be notified about</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {[
                        {
                          label: "Critical vulnerabilities",
                          desc: "Immediate alerts for critical issues",
                          checked: notifyCritical,
                          onChange: setNotifyCritical,
                        },
                        {
                          label: "Weekly digest",
                          desc: "Summary of all scans and issues",
                          checked: notifyWeekly,
                          onChange: setNotifyWeekly,
                        },
                      ].map((item) => (
                        <div key={item.label} className="flex items-center justify-between">
                          <div>
                            <p className="font-medium text-sm">{item.label}</p>
                            <p className="text-xs text-muted-foreground">{item.desc}</p>
                          </div>
                          <button
                            onClick={() => item.onChange(!item.checked)}
                            className={cn(
                              "w-10 h-6 rounded-full transition-colors relative",
                              item.checked ? "bg-primary" : "bg-muted"
                            )}
                          >
                            <span
                              className={cn(
                                "absolute top-1 w-4 h-4 rounded-full bg-white transition-transform",
                                item.checked ? "translate-x-5" : "translate-x-1"
                              )}
                            />
                          </button>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </motion.div>
              )}

              {activeTab === "scanning" && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-6"
                >
                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">Scheduled Scans</CardTitle>
                      <CardDescription>Automate your security scanning</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {scanSchedules.map((schedule) => (
                        <div
                          key={schedule.repo}
                          className="flex items-center gap-4 p-3 rounded-lg bg-secondary/50"
                        >
                          <Calendar className="w-5 h-5 text-muted-foreground" />
                          <div className="flex-1">
                            <p className="font-medium text-sm">{schedule.repo}</p>
                            <div className="flex items-center gap-2 text-xs text-muted-foreground">
                              <Clock className="w-3 h-3" />
                              {schedule.frequency} - {schedule.time}
                            </div>
                          </div>
                          <span
                            className={cn(
                              "px-2 py-0.5 text-xs rounded-full",
                              schedule.active
                                ? "bg-success/10 text-success"
                                : "bg-muted text-muted-foreground"
                            )}
                          >
                            {schedule.active ? "Active" : "Paused"}
                          </span>
                          <Button variant="ghost" size="sm">
                            Edit
                          </Button>
                        </div>
                      ))}
                      <Button variant="outline" className="w-full gap-2">
                        <Plus className="w-4 h-4" />
                        Add Schedule
                      </Button>
                    </CardContent>
                  </Card>

                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">Scan Configuration</CardTitle>
                      <CardDescription>Default settings for all scans</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">Include dependencies</p>
                          <p className="text-xs text-muted-foreground">Scan node_modules for vulnerabilities</p>
                        </div>
                        <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-primary/10 text-primary text-sm">
                          <Check className="w-4 h-4" />
                          Enabled
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">AI-powered analysis</p>
                          <p className="text-xs text-muted-foreground">Use LLMs for deeper code understanding</p>
                        </div>
                        <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-primary/10 text-primary text-sm">
                          <Check className="w-4 h-4" />
                          Enabled
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}

              {activeTab === "api" && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-6"
                >
                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">API Keys</CardTitle>
                      <CardDescription>Manage API keys for programmatic access</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="p-4 rounded-lg bg-secondary/50 space-y-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="font-medium text-sm">Production Key</p>
                            <p className="text-xs text-muted-foreground">Created 30 days ago</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <code className="text-xs bg-background px-2 py-1 rounded font-mono">
                              vs_live_****...****
                            </code>
                            <Button variant="ghost" size="sm">
                              Reveal
                            </Button>
                          </div>
                        </div>
                      </div>

                      <Button variant="outline" className="w-full gap-2">
                        <Plus className="w-4 h-4" />
                        Generate New Key
                      </Button>
                    </CardContent>
                  </Card>

                  <Card className="bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                      <CardTitle className="text-base">API Documentation</CardTitle>
                      <CardDescription>Learn how to use the VibeShield API</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Button variant="outline" className="gap-2">
                        <ExternalLink className="w-4 h-4" />
                        View API Docs
                      </Button>
                    </CardContent>
                  </Card>
                </motion.div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
