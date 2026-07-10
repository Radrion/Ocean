import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Download, FileJson, Shield, Search, Zap, CheckCircle2, XCircle, Copy, Terminal, Table2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

const sampleAlert = {
  timestamp: "2026-07-10T15:24:18.684+0000",
  id: "1694607138.3688437",
  agent: { id: "002", name: "WIN-ENDPOINT-01", ip: "10.0.12.44" },
  manager: { name: "wazuh-manager" },
  rule: {
    id: "110011",
    level: 10,
    description: "Possible suspicious service creation detected",
    groups: ["windows", "sysmon", "persistence"],
    mitre: {
      id: ["T1543.003"],
      tactic: ["Persistence", "Privilege Escalation"],
      technique: ["Windows Service"]
    }
  },
  decoder: { name: "windows_eventchannel" },
  location: "EventChannel",
  data: {
    win: {
      eventdata: {
        user: "NT AUTHORITY\\SYSTEM",
        image: "C:\\Windows\\system32\\services.exe",
        targetObject: "HKLM\\System\\CurrentControlSet\\Services\\ExampleSvc\\ObjectName",
        eventType: "SetValue"
      },
      system: {
        eventID: "13",
        channel: "Microsoft-Windows-Sysmon/Operational",
        computer: "WIN-ENDPOINT-01"
      }
    }
  }
};

function safeGet(obj, path, fallback = "Not present in alert") {
  try {
    const result = path.split(".").reduce((acc, key) => acc?.[key], obj);
    if (Array.isArray(result)) return result.join(", ");
    return result || fallback;
  } catch {
    return fallback;
  }
}

function riskLabel(level) {
  const n = Number(level || 0);
  if (n >= 12) return { label: "Critical", color: "text-red-400", bg: "bg-red-500/10 border-red-500/30" };
  if (n >= 9) return { label: "High", color: "text-orange-300", bg: "bg-orange-500/10 border-orange-500/30" };
  if (n >= 6) return { label: "Medium", color: "text-yellow-300", bg: "bg-yellow-500/10 border-yellow-500/30" };
  if (n >= 3) return { label: "Low", color: "text-blue-300", bg: "bg-blue-500/10 border-blue-500/30" };
  return { label: "Informational", color: "text-slate-300", bg: "bg-slate-500/10 border-slate-500/30" };
}

function parseAlert(text) {
  try {
    return { ok: true, data: JSON.parse(text), error: null };
  } catch (e) {
    return { ok: false, data: null, error: e.message };
  }
}

export default function WazuhAlertAnalyzerInterface() {
  const [rawAlert, setRawAlert] = useState(JSON.stringify(sampleAlert, null, 2));
  const [activeTab, setActiveTab] = useState("summary");
  const [copied, setCopied] = useState(false);

  const parsed = useMemo(() => parseAlert(rawAlert), [rawAlert]);
  const alert = parsed.data || {};
  const level = safeGet(alert, "rule.level", "0");
  const risk = riskLabel(level);

  const mitreRows = useMemo(() => {
    const ids = alert?.rule?.mitre?.id || [];
    const tactics = alert?.rule?.mitre?.tactic || [];
    const techniques = alert?.rule?.mitre?.technique || [];
    if (!ids.length && !tactics.length && !techniques.length) {
      return [{ tactic: "Not present", id: "Not present", technique: "Not present", evidence: "No rule.mitre mapping found", confidence: "Low" }];
    }
    const max = Math.max(ids.length, tactics.length, techniques.length);
    return Array.from({ length: max }).map((_, i) => ({
      tactic: tactics[i] || tactics[0] || "Not present",
      id: ids[i] || ids[0] || "Not present",
      technique: techniques[i] || techniques[0] || "Not present",
      evidence: safeGet(alert, "rule.description"),
      confidence: ids.length ? "High" : "Medium"
    }));
  }, [alert]);

  const keyFields = [
    ["Time", safeGet(alert, "timestamp")],
    ["Agent", `${safeGet(alert, "agent.name")} / ${safeGet(alert, "agent.ip")} / ID ${safeGet(alert, "agent.id")}`],
    ["Manager", safeGet(alert, "manager.name")],
    ["Rule ID", safeGet(alert, "rule.id")],
    ["Rule Level", safeGet(alert, "rule.level")],
    ["Rule Description", safeGet(alert, "rule.description")],
    ["Decoder", safeGet(alert, "decoder.name")],
    ["Location", safeGet(alert, "location")],
    ["User", safeGet(alert, "data.win.eventdata.user")],
    ["Process", safeGet(alert, "data.win.eventdata.image")],
    ["Source IP", safeGet(alert, "srcip")],
    ["Destination IP", safeGet(alert, "dstip")],
    ["File / Registry / Command", safeGet(alert, "data.win.eventdata.targetObject")],
    ["MITRE Mapping", safeGet(alert, "rule.mitre.id")]
  ];

  const report = `Wazuh Alert Analysis\n\nExecutive Summary\n${safeGet(alert, "rule.description")} on ${safeGet(alert, "agent.name")} with Wazuh level ${safeGet(alert, "rule.level")}. Risk label: ${risk.label}.\n\nMITRE Mapping\n${mitreRows.map(r => `- ${r.tactic} | ${r.id} | ${r.technique} | Confidence: ${r.confidence}`).join("\n")}\n\nRecommended Investigation Steps\n- Review related Wazuh alerts around the same timestamp.\n- Validate user, host, process, command line, file path, registry path, and network context.\n- Confirm whether activity matches approved administration or software deployment.\n- Preserve evidence before remediation if compromise is suspected.\n\nContainment and Remediation\n- Isolate the host if active compromise is suspected.\n- Disable or reset affected credentials if credential misuse is suspected.\n- Remove unauthorized persistence only after evidence collection.\n- Patch, harden, and improve detections as needed.\n`;

  const exportReport = () => {
    const blob = new Blob([report], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "wazuh-alert-analysis.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyReport = async () => {
    await navigator.clipboard.writeText(report);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  const tabs = [
    ["summary", "Summary", Shield],
    ["mitre", "MITRE", Table2],
    ["investigate", "Investigate", Search],
    ["remediate", "Remediate", Zap]
  ];

  return (
    <div className="min-h-screen bg-[#1e1e1e] text-[#d4d4d4] font-mono p-4 md:p-6">
      <div className="max-w-7xl mx-auto space-y-4">
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border border-[#3c3c3c] bg-[#252526] rounded-2xl p-4 shadow-2xl">
          <div>
            <div className="flex items-center gap-2 text-[#569cd6] text-sm uppercase tracking-widest">
              <Terminal size={16} /> Wazuh SOC Console
            </div>
            <h1 className="text-2xl md:text-3xl font-semibold text-[#cccccc] mt-1">Alert Analyzer</h1>
            <p className="text-[#9cdcfe] text-sm mt-1">Paste Wazuh JSON, analyze risk, map MITRE ATT&CK, and export a triage report.</p>
          </div>
          <div className={`border rounded-xl px-4 py-3 ${risk.bg}`}>
            <div className="text-xs text-[#808080]">Current Risk</div>
            <div className={`text-xl font-bold ${risk.color}`}>{parsed.ok ? risk.label : "Invalid JSON"}</div>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card className="bg-[#1e1e1e] border-[#3c3c3c] rounded-2xl shadow-xl overflow-hidden">
            <CardContent className="p-0">
              <div className="bg-[#252526] border-b border-[#3c3c3c] px-4 py-3 flex items-center justify-between">
                <div className="flex items-center gap-2 text-[#ce9178]"><FileJson size={18} /> alert.json</div>
                <Button variant="ghost" className="text-[#9cdcfe] hover:bg-[#2d2d30]" onClick={() => setRawAlert(JSON.stringify(sampleAlert, null, 2))}>Load Sample</Button>
              </div>
              <textarea
                value={rawAlert}
                onChange={(e) => setRawAlert(e.target.value)}
                spellCheck={false}
                className="w-full h-[560px] bg-[#1e1e1e] text-[#d4d4d4] p-4 outline-none resize-none text-sm leading-6 selection:bg-[#264f78]"
              />
              {!parsed.ok && (
                <div className="border-t border-red-500/30 bg-red-500/10 text-red-300 px-4 py-3 flex gap-2 text-sm">
                  <XCircle size={16} /> JSON parse error: {parsed.error}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-[#1e1e1e] border-[#3c3c3c] rounded-2xl shadow-xl overflow-hidden">
            <CardContent className="p-0">
              <div className="bg-[#252526] border-b border-[#3c3c3c] px-3 py-2 flex flex-wrap gap-2">
                {tabs.map(([id, label, Icon]) => (
                  <button key={id} onClick={() => setActiveTab(id)} className={`flex items-center gap-2 px-3 py-2 rounded-xl text-sm border ${activeTab === id ? "bg-[#094771] border-[#007acc] text-white" : "bg-[#1e1e1e] border-[#3c3c3c] text-[#cccccc] hover:bg-[#2d2d30]"}`}>
                    <Icon size={15} /> {label}
                  </button>
                ))}
              </div>

              <div className="p-4 h-[620px] overflow-auto">
                {activeTab === "summary" && (
                  <div className="space-y-4">
                    <section className="border border-[#3c3c3c] rounded-2xl p-4 bg-[#252526]">
                      <h2 className="text-[#4ec9b0] text-lg font-semibold mb-2">Executive Summary</h2>
                      <p className="text-sm leading-6">
                        <span className="text-[#dcdcaa]">{safeGet(alert, "rule.description")}</span> was observed on <span className="text-[#9cdcfe]">{safeGet(alert, "agent.name")}</span>. Wazuh rule level is <span className={risk.color}>{level}</span>, currently labeled <span className={risk.color}>{risk.label}</span>. Confidence depends on corroborating host, user, process, and related-alert evidence.
                      </p>
                    </section>

                    <section className="border border-[#3c3c3c] rounded-2xl overflow-hidden">
                      <div className="bg-[#252526] px-4 py-3 text-[#4fc1ff] font-semibold">Key Alert Fields</div>
                      <div className="divide-y divide-[#3c3c3c]">
                        {keyFields.map(([k, v]) => (
                          <div key={k} className="grid grid-cols-3 gap-3 px-4 py-2 text-sm">
                            <div className="text-[#569cd6]">{k}</div>
                            <div className="col-span-2 break-words text-[#d4d4d4]">{v}</div>
                          </div>
                        ))}
                      </div>
                    </section>
                  </div>
                )}

                {activeTab === "mitre" && (
                  <div className="space-y-4">
                    <div className="border border-[#3c3c3c] rounded-2xl p-4 bg-[#252526]">
                      <h2 className="text-[#4ec9b0] text-lg font-semibold">MITRE ATT&CK Mapping</h2>
                      <p className="text-sm text-[#c586c0] mt-1">Uses explicit <code className="text-[#ce9178]">rule.mitre</code> fields when available. Manual inference should be labeled tentative.</p>
                    </div>
                    <div className="overflow-auto border border-[#3c3c3c] rounded-2xl">
                      <table className="w-full text-sm">
                        <thead className="bg-[#252526] text-[#9cdcfe]">
                          <tr>
                            <th className="text-left p-3">Tactic</th>
                            <th className="text-left p-3">Technique ID</th>
                            <th className="text-left p-3">Technique</th>
                            <th className="text-left p-3">Evidence</th>
                            <th className="text-left p-3">Confidence</th>
                          </tr>
                        </thead>
                        <tbody>
                          {mitreRows.map((row, i) => (
                            <tr key={i} className="border-t border-[#3c3c3c] hover:bg-[#2d2d30]">
                              <td className="p-3 text-[#c586c0]">{row.tactic}</td>
                              <td className="p-3 text-[#dcdcaa]">{row.id}</td>
                              <td className="p-3 text-[#4ec9b0]">{row.technique}</td>
                              <td className="p-3">{row.evidence}</td>
                              <td className="p-3 text-[#b5cea8]">{row.confidence}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {activeTab === "investigate" && (
                  <Checklist title="Recommended Investigation Steps" color="text-[#4fc1ff]" items={[
                    "Review related Wazuh alerts for the same host, user, source IP, rule group, and time window.",
                    "Validate whether the user and process activity match expected administration or deployment behavior.",
                    "Check process lineage, command line, parent process, hashes, file path, registry path, and network connections.",
                    "Confirm asset criticality, exposure, business function, and whether the host handles sensitive data.",
                    "Search for the same rule, IOC, process, user, or registry path across other endpoints.",
                    "Preserve relevant logs and endpoint evidence before containment when compromise is plausible."
                  ]} />
                )}

                {activeTab === "remediate" && (
                  <div className="space-y-4">
                    <Checklist title="Containment and Remediation" color="text-[#f48771]" items={[
                      "Isolate the endpoint if active compromise is suspected.",
                      "Disable, reset, or rotate affected credentials if account misuse is suspected.",
                      "Block confirmed malicious IPs, domains, hashes, or file paths after validation.",
                      "Remove unauthorized persistence only after evidence collection.",
                      "Patch vulnerable software and harden affected configurations.",
                      "Add or tune detections, then validate that the activity no longer appears."
                    ]} />
                    <Checklist title="False Positive Considerations" color="text-[#dcdcaa]" items={[
                      "Was this caused by approved IT administration, software deployment, patching, or monitoring tools?",
                      "Does the account normally perform this action on this asset?",
                      "Is the process path signed, expected, and consistent with normal baselines?",
                      "Are there related suspicious alerts before or after this event?"
                    ]} />
                  </div>
                )}
              </div>

              <div className="bg-[#252526] border-t border-[#3c3c3c] p-3 flex flex-wrap gap-2 justify-end">
                <Button onClick={copyReport} className="bg-[#0e639c] hover:bg-[#1177bb] text-white rounded-xl">
                  {copied ? <CheckCircle2 size={16} className="mr-2" /> : <Copy size={16} className="mr-2" />} {copied ? "Copied" : "Copy Report"}
                </Button>
                <Button onClick={exportReport} className="bg-[#16825d] hover:bg-[#1f9d72] text-white rounded-xl">
                  <Download size={16} className="mr-2" /> Export Report
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Checklist({ title, items, color }) {
  return (
    <div className="border border-[#3c3c3c] rounded-2xl overflow-hidden bg-[#1e1e1e]">
      <div className={`bg-[#252526] px-4 py-3 font-semibold ${color}`}>{title}</div>
      <div className="p-4 space-y-3">
        {items.map((item, idx) => (
          <motion.div key={item} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.03 }} className="flex gap-3 text-sm leading-6">
            <AlertTriangle size={16} className="text-[#dcdcaa] flex-none mt-1" />
            <span>{item}</span>
          </motion.div>
        ))}
      </div>
    </div>
  );
}