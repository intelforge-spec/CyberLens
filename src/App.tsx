import React, { useState, useEffect } from "react";
import { jsPDF } from "jspdf";
import { 
  Shield, 
  ShieldAlert, 
  Cpu, 
  AlertTriangle, 
  Network, 
  Search, 
  Mail, 
  History, 
  BookOpen,
  CheckCircle, 
  XCircle, 
  AlertCircle, 
  Globe, 
  Link2, 
  Hash, 
  ExternalLink, 
  Trash2, 
  Zap, 
  FileText, 
  Download, 
  Eye, 
  CornerDownRight, 
  ArrowRight,
  RefreshCw,
  Terminal,
  Clock,
  Briefcase,
  FileSpreadsheet,
  Users,
  Settings,
  ClipboardList,
  LogOut,
  KeyRound,
  Lock
} from "lucide-react";
import DashboardView from "./components/DashboardView";
import LoginView from "./components/LoginView";
import UserManagementView from "./components/UserManagementView";
import IntegrationSettingsView from "./components/IntegrationSettingsView";
import AuditLogsView from "./components/AuditLogsView";
import { InvestigationRecord, EmailAnalysisRecord, IOCType } from "./types";

export default function App() {
  const [activeTab, setActiveTab] = useState<"dashboard" | "lookup" | "email" | "logs" | "users" | "integrations" | "auditLogs">("dashboard");
  const [records, setRecords] = useState<InvestigationRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Authentication States
  const [token, setToken] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<{ id: string; username: string; role: "Admin" | "Analyst" | "Viewer"; createdAt: string } | null>(null);

  // Change Password States
  const [showPasswordChange, setShowPasswordChange] = useState(false);
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [changePasswordError, setChangePasswordError] = useState<string | null>(null);
  const [changePasswordSuccess, setChangePasswordSuccess] = useState<string | null>(null);
  const [changingPassword, setChangingPassword] = useState(false);

  // IOC Lookup States
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedRecord, setSelectedRecord] = useState<InvestigationRecord | null>(null);

  // Email Analyzer States
  const [emailRawInput, setEmailRawInput] = useState("");
  const [analyzingEmail, setAnalyzingEmail] = useState(false);
  const [emailAnalysisResult, setEmailAnalysisResult] = useState<EmailAnalysisRecord | null>(null);
  const [uploadedFilename, setUploadedFilename] = useState("phishing_sample.eml");
  const [selectedLogIds, setSelectedLogIds] = useState<string[]>([]);

  // Custom Toast and Dialog Modal States to bypass iframe restrictions
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" | "info" } | null>(null);
  const [confirmDialog, setConfirmDialog] = useState<{
    title: string;
    message: string;
    onConfirm: () => void;
  } | null>(null);

  const showToast = (message: string, type: "success" | "error" | "info" = "success") => {
    setToast({ message, type });
    setTimeout(() => {
      setToast(null);
    }, 4500);
  };

  // Load session from local storage on mount
  useEffect(() => {
    const savedToken = localStorage.getItem("cyberlens_token");
    const savedUser = localStorage.getItem("cyberlens_user");
    if (savedToken && savedUser) {
      try {
        setToken(savedToken);
        setCurrentUser(JSON.parse(savedUser));
      } catch {
        localStorage.removeItem("cyberlens_token");
        localStorage.removeItem("cyberlens_user");
      }
    }
  }, []);

  // Fetch initial logs on session load
  useEffect(() => {
    if (token) {
      fetchLogs();
    }
  }, [token]);

  const fetchLogs = async () => {
    if (!token) return;
    try {
      const res = await fetch("/api/investigations", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (res.status === 401 || res.status === 403) {
        handleLogout();
        return;
      }
      if (res.ok) {
        const data = await res.json();
        setRecords(data);
      }
    } catch (e) {
      console.error("Error loading investigations list", e);
    }
  };

  const handleSelectRecord = (record: InvestigationRecord) => {
    setSelectedRecord(record);
    setActiveTab("lookup");
    setSearchQuery(record.ioc);
  };

  const handleIOCOnceSet = (iocValue: string) => {
    setSearchQuery(iocValue);
    setSelectedRecord(null);
    setActiveTab("lookup");
  };

  // Perform IOC Lookup Query
  const handleIOCSearchSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    if (currentUser?.role === "Viewer") {
      setError("Akses Ditolak: Akun Anda memiliki izin terbatas (Viewer) sehingga tidak diperkenankan mengajukan kueri investigasi.");
      return;
    }

    setLoading(true);
    setError(null);
    setSelectedRecord(null);

    try {
      const res = await fetch("/api/investigations", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ ioc: searchQuery.trim() })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Threat intelligence API query returned error status");
      }

      const result = await res.json();
      setSelectedRecord(result);
      fetchLogs();
    } catch (err: any) {
      setError(err.message || "Failed to contact CyberLens intelligence database.");
    } finally {
      setLoading(false);
    }
  };

  // Email Paste trigger
  const handleEmailAnalyzeSubmit = async (customContent?: string, nameOfFile?: string) => {
    const rawToUse = customContent || emailRawInput;
    if (!rawToUse.trim()) {
      showToast("Please paste EML raw text contents first.", "info");
      return;
    }

    if (currentUser?.role === "Viewer") {
      setError("Akses Ditolak: Akun Anda memiliki izin terbatas (Viewer) sehingga tidak diperkenankan menjalankan analisis email rekayasa sosial.");
      return;
    }

    setAnalyzingEmail(true);
    setError(null);
    setEmailAnalysisResult(null);

    try {
      const res = await fetch("/api/email-analyze", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ 
          rawEmailContent: rawToUse,
          filename: nameOfFile || uploadedFilename
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Phishing analysis engine returned code error.");
      }

      const result = await res.json();
      setEmailAnalysisResult(result);
      fetchLogs(); // Sync to main Dashboard
    } catch (err: any) {
      setError(err.message || "Threat analyzer aborted execution during SMTP diagnostics.");
    } finally {
      setAnalyzingEmail(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` }
      });
    } catch (e) {
      console.error("Gagal melakukan audit kelogoutan", e);
    }
    localStorage.removeItem("cyberlens_token");
    localStorage.removeItem("cyberlens_user");
    setToken(null);
    setCurrentUser(null);
    setActiveTab("dashboard");
  };

  const handleExportIncidentPDF = (record: InvestigationRecord) => {
    const doc = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4"
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;
    const contentWidth = pageWidth - (margin * 2);
    let y = 20;

    // Helper functions for consistent layout
    const addHeader = (title: string) => {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(22);
      doc.setTextColor(15, 23, 42); // Deep slate
      doc.text(title, margin, y);
      y += 6;
      doc.setDrawColor(226, 232, 240); // slate-200
      doc.setLineWidth(0.5);
      doc.line(margin, y, pageWidth - margin, y);
      y += 8;
    };

    const addSectionHeader = (title: string) => {
      if (y > pageHeight - 30) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "bold");
      doc.setFontSize(14);
      doc.setTextColor(30, 58, 138); // Navy
      doc.text(title, margin, y);
      y += 4;
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.3);
      doc.line(margin, y, pageWidth - margin, y);
      y += 6;
    };

    const addMetaRow = (label: string, value: string) => {
      if (y > pageHeight - 15) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(71, 85, 105); // slate-600
      doc.text(label, margin, y);
      
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42); // slate-900
      
      const valLines = doc.splitTextToSize(value, contentWidth - 45);
      doc.text(valLines, margin + 45, y);
      y += (valLines.length * 5) + 2;
    };

    const addParagraph = (text: string) => {
      if (!text) return;
      if (y > pageHeight - 20) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85); // slate-700
      
      const lines = doc.splitTextToSize(text, contentWidth);
      doc.text(lines, margin, y);
      y += (lines.length * 5) + 4;
    };

    const addBullet = (bulletText: string) => {
      if (y > pageHeight - 15) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      
      // Draw blue bullet point
      doc.setFillColor(37, 99, 235); // blue-600
      doc.circle(margin + 2, y - 1, 0.8, "F");

      const lines = doc.splitTextToSize(bulletText, contentWidth - 8);
      doc.text(lines, margin + 6, y);
      y += (lines.length * 5) + 3;
    };

    // Begin Document with styled horizontal bar
    doc.setFillColor(29, 78, 216); // Blue-700
    doc.rect(0, 0, pageWidth, 4, "F");
    y += 10;

    // Header Title
    addHeader("CYBERLENS INCIDENT REPORT");

    // Section 1: Overview
    addSectionHeader("1. Investigation Brief Overview");
    addMetaRow("Indicator (IOC):", record.ioc);
    addMetaRow("Indicator Type:", record.type.toUpperCase());
    addMetaRow("Threat Score:", `${record.riskScore} / 100`);
    addMetaRow("Risk Severity:", record.severity.toUpperCase());
    addMetaRow("Timestamp (UTC):", new Date(record.timestamp).toUTCString());
    y += 4;

    // Section 2: AI Summary
    if (record.aiSummary) {
      addSectionHeader("2. Incident Intelligence Analysis");
      
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(30, 41, 59);
      doc.text("Executive Summary:", margin, y);
      y += 5;
      addParagraph(record.aiSummary.investigationSummary);

      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(30, 41, 59);
      doc.text("Threat Assessment & Potential Risk:", margin, y);
      y += 5;
      addParagraph(record.aiSummary.threatAssessment);
    }

    // Section 3: Recommended Actions
    if (record.aiSummary?.recommendedActions && record.aiSummary.recommendedActions.length > 0) {
      addSectionHeader("3. Recommended Remediation Procedures");
      record.aiSummary.recommendedActions.forEach((act) => {
        addBullet(act);
      });
      y += 4;
    }

    // Section 4: Supporting Intel Details
    addSectionHeader("4. Threat Intelligence Details & Context");
    const intel = record.threatIntel;
    addMetaRow("Reputation Status:", intel.reputation || "N/A");
    if (intel.organization) addMetaRow("Organization / ISP:", intel.organization);
    if (intel.asn) addMetaRow("ASN Details:", intel.asn);
    if (intel.country) addMetaRow("Geographic Country:", `${intel.country} (${intel.countryCode || ""})`);
    if (intel.domainAge) addMetaRow("Domain Age / Registered:", intel.domainAge);
    if (intel.malwareFamily) addMetaRow("Detected Malware Family:", intel.malwareFamily);
    if (intel.otxPulseCount !== undefined) addMetaRow("OTX Global Indicators (Pulses):", `${intel.otxPulseCount} pulse matches`);
    
    // Add page numbers footer
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFont("helvetica", "italic");
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184); // slate-400
      doc.text(`CyberLens Cybersecurity Platform - Page ${i} of ${pageCount}`, margin, pageHeight - 10);
      doc.text(`Generated on: ${new Date().toUTCString()} (UTC)`, pageWidth - margin - 50, pageHeight - 10);
    }

    doc.save(`CyberLens-IncidentReport-${record.ioc}.pdf`);
  };

  const handleExportPhishingPDF = (record: EmailAnalysisRecord) => {
    const doc = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4"
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;
    const contentWidth = pageWidth - (margin * 2);
    let y = 20;

    const addHeader = (title: string) => {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(20);
      doc.setTextColor(15, 23, 42); // Deep slate
      doc.text(title, margin, y);
      y += 6;
      doc.setDrawColor(226, 232, 240); // slate-200
      doc.setLineWidth(0.5);
      doc.line(margin, y, pageWidth - margin, y);
      y += 8;
    };

    const addSectionHeader = (title: string) => {
      if (y > pageHeight - 30) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "bold");
      doc.setFontSize(14);
      doc.setTextColor(30, 58, 138); // Navy
      doc.text(title, margin, y);
      y += 4;
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.3);
      doc.line(margin, y, pageWidth - margin, y);
      y += 6;
    };

    const addMetaRow = (label: string, value: string) => {
      if (y > pageHeight - 15) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(71, 85, 105); // slate-600
      doc.text(label, margin, y);
      
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42); // slate-900
      
      const valLines = doc.splitTextToSize(value, contentWidth - 45);
      doc.text(valLines, margin + 45, y);
      y += (valLines.length * 5) + 2;
    };

    const addParagraph = (text: string) => {
      if (!text) return;
      if (y > pageHeight - 20) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85); // slate-700
      
      const lines = doc.splitTextToSize(text, contentWidth);
      doc.text(lines, margin, y);
      y += (lines.length * 5) + 4;
    };

    const addBullet = (bulletText: string) => {
      if (y > pageHeight - 15) {
        doc.addPage();
        y = 20;
      }
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      
      doc.setFillColor(220, 38, 38); // red-600
      doc.circle(margin + 2, y - 1, 0.8, "F");

      const lines = doc.splitTextToSize(bulletText, contentWidth - 8);
      doc.text(lines, margin + 6, y);
      y += (lines.length * 5) + 3;
    };

    doc.setFillColor(185, 28, 28); // Red-700 for alerts
    doc.rect(0, 0, pageWidth, 4, "F");
    y += 10;

    addHeader("CYBERLENS PHISHING FORENSIC ANALYSIS");

    addSectionHeader("1. Analytical Assessment Summary");
    addMetaRow("File EML Target:", record.filename);
    addMetaRow("Email Subject:", record.subject);
    addMetaRow("Forensic Threat Score:", `${record.riskScore} / 100`);
    addMetaRow("Phishing Severity:", record.severity.toUpperCase());
    addMetaRow("Analysis Timestamp:", new Date(record.timestamp).toUTCString());
    y += 4;

    if (record.aiSummary) {
      addSectionHeader("2. Phishing Campaign Intelligence");
      
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(30, 41, 59);
      doc.text("Executive Forensic Summary:", margin, y);
      y += 5;
      addParagraph(record.aiSummary.investigationSummary);

      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(30, 41, 59);
      doc.text("Malicious Intent Assessment:", margin, y);
      y += 5;
      addParagraph(record.aiSummary.threatAssessment);
    }

    if (record.aiSummary?.recommendedActions && record.aiSummary.recommendedActions.length > 0) {
      addSectionHeader("3. Tactical Containment & Remediation Guidelines");
      record.aiSummary.recommendedActions.forEach((act) => {
        addBullet(act);
      });
      y += 4;
    }

    addSectionHeader("4. Email Metadata and Headers Trace");
    addMetaRow("Delivered From:", record.headers.from || "N/A");
    addMetaRow("Reply-To Routing:", record.headers.replyTo || "N/A");
    addMetaRow("Return-Path Header:", record.headers.returnPath || "N/A");
    if (record.headers.receivedChain && record.headers.receivedChain.length > 0) {
      addMetaRow("Transit Hop Count:", `${record.headers.receivedChain.length} hops detected`);
    }

    addSectionHeader("5. Threat Authentication Checks (SPF, DKIM, DMARC)");
    addMetaRow("SPF Status:", `${record.auth.spf.status} (${record.auth.spf.details || "No details"})`);
    addMetaRow("DKIM Status:", `${record.auth.dkim.status} (${record.auth.dkim.details || "No details"})`);
    addMetaRow("DMARC Status:", `${record.auth.dmarc.status} (${record.auth.dmarc.details || "No details"})`);
    y += 4;

    if (record.urls && record.urls.length > 0) {
      addSectionHeader("6. Extracted URL Links Scan Results");
      record.urls.forEach((urlObj, idx) => {
        addMetaRow(`URL Link #${idx + 1}:`, urlObj.url);
        addMetaRow(`Scan Verdict:`, `URLHausHit=${urlObj.urlhausHit}, OTX Pulses=${urlObj.otxPulses}, Status=${urlObj.urlscanStatus}`);
        y += 2;
      });
    }

    if (record.attachments && record.attachments.length > 0) {
      addSectionHeader("7. Extracted Files & Attachments Forensic Details");
      record.attachments.forEach((att, idx) => {
        addMetaRow(`Attachment #${idx + 1}:`, att.filename);
        addMetaRow(`File Hash (SHA-256):`, att.sha256);
        addMetaRow(`Malware Match:`, `Verdict=${att.malwareBazaarMatch ? "Malicious" : "Clean"} (Family=${att.malwareFamily || "None"}), Size=${att.size}`);
        y += 2;
      });
    }

    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFont("helvetica", "italic");
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184); // slate-400
      doc.text(`CyberLens Forensic Toolkit - Page ${i} of ${pageCount}`, margin, pageHeight - 10);
      doc.text(`Generated on: ${new Date().toUTCString()} (UTC)`, pageWidth - margin - 50, pageHeight - 10);
    }

    doc.save(`CyberLens-EmailForensicReport-${record.filename}.pdf`);
  };

  const handleDeleteSingleLog = async (id: string) => {
    if (currentUser?.role === "Viewer") {
      showToast("Akses Ditolak: Peran Viewer tidak diperkenankan menghapus data.", "error");
      return;
    }

    setConfirmDialog({
      title: "Konfirmasi Hapus Investigasi",
      message: "Apakah Anda yakin ingin menghapus catatan investigasi ini?",
      onConfirm: async () => {
        try {
          const res = await fetch("/api/investigations/delete-selected", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({ ids: [id] })
          });
          if (!res.ok) {
            throw new Error("Gagal menghapus log dari basis data.");
          }
          await fetchLogs();
          setSelectedLogIds(prev => prev.filter(item => item !== id));
          showToast("Catatan investigasi berhasil dihapus.", "success");
        } catch (e: any) {
          showToast(e.message || "Gagal melakukan penghapusan.", "error");
        }
      }
    });
  };

  const handleDeleteSelected = async () => {
    if (selectedLogIds.length === 0) {
      showToast("Silakan pilih minimal satu item untuk dihapus.", "info");
      return;
    }
    
    if (currentUser?.role === "Viewer") {
      showToast("Akses Ditolak: Peran Viewer tidak diperkenankan menghapus data.", "error");
      return;
    }

    setConfirmDialog({
      title: "Konfirmasi Hapus Beberapa Riwayat",
      message: `Apakah Anda yakin ingin menghapus ${selectedLogIds.length} item riwayat terpilih?`,
      onConfirm: async () => {
        try {
          const res = await fetch("/api/investigations/delete-selected", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({ ids: selectedLogIds })
          });
          if (!res.ok) {
            throw new Error("Gagal menghapus log terpilih dari basis data.");
          }
          await fetchLogs();
          setSelectedLogIds([]);
          showToast("Item terpilih berhasil dihapus.", "success");
        } catch (e: any) {
          showToast(e.message || "Gagal melakukan penghapusan.", "error");
        }
      }
    });
  };

  const handleDeleteAll = async () => {
    if (records.length === 0) {
      showToast("Tidak ada riwayat untuk dihapus.", "info");
      return;
    }

    if (currentUser?.role === "Viewer") {
      showToast("Akses Ditolak: Peran Viewer tidak diperkenankan menghapus data.", "error");
      return;
    }

    setConfirmDialog({
      title: "Konfirmasi Hapus Seluruh Riwayat",
      message: "Apakah Anda yakin ingin menghapus SELURUH riwayat investigasi dan basis data ancaman?",
      onConfirm: async () => {
        try {
          const res = await fetch("/api/investigations/delete-all", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${token}`
            }
          });
          if (!res.ok) {
            throw new Error("Gagal menghapus seluruh log dari basis data.");
          }
          await fetchLogs();
          setSelectedLogIds([]);
          showToast("Seluruh riwayat berhasil dibersihkan.", "success");
        } catch (e: any) {
          showToast(e.message || "Gagal membersihkan riwayat.", "error");
        }
      }
    });
  };

  const handleExportCSV = () => {
    if (records.length === 0) {
      showToast("Tidak ada data untuk diekspor ke CSV.", "info");
      return;
    }

    const headers = ["ID", "Indicator Target", "Indicator Type", "Threat Score", "Severity", "Timestamp", "Summary"];
    const rows = records.map(rec => [
      rec.id || "",
      rec.ioc || "",
      rec.type || "",
      rec.riskScore !== undefined ? rec.riskScore.toString() : "",
      rec.severity || "",
      rec.timestamp || "",
      rec.aiSummary?.investigationSummary ? rec.aiSummary.investigationSummary.replace(/"/g, '""') : ""
    ]);

    const csvContent = "\uFEFF" + [  // Include BOM for proper Excel encoding of Indonesian characters
      headers.join(","),
      ...rows.map(e => e.map(val => `"${val}"`).join(","))
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `cyberlens_investigation_export_${new Date().toISOString().slice(0,10)}.csv`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleChangePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!oldPassword || !newPassword) {
      setChangePasswordError("Semua kolom kata sandi wajib diisi.");
      return;
    }

    setChangingPassword(true);
    setChangePasswordError(null);
    setChangePasswordSuccess(null);

    try {
      const res = await fetch("/api/auth/change-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ currentPassword: oldPassword, newPassword })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Gagal memperbarui kata sandi.");
      }

      setChangePasswordSuccess("Kata sandi berhasil diubah secara aman.");
      setOldPassword("");
      setNewPassword("");
    } catch (err: any) {
      setChangePasswordError(err.message);
    } finally {
      setChangingPassword(false);
    }
  };

  // Premade simulation email templates
  const SPAM_TEMPLATES = [
    {
      title: "DHL Spoof Phishing (ZIP Dropper)",
      filename: "dhl_invoice_suspicion.eml",
      content: `Received: from mail-attacker.premium-bonus-rewards.xyz (premium-bonus-rewards.xyz [104.21.36.108])
From: DHL Express Team <delivery-updates-notification@premium-bonus-rewards.xyz>
Reply-To: attacker-mailbox@protonmail.com
Return-Path: bounced-delivery@premium-bonus-rewards.xyz
Subject: URGENT: Your DHL Package #8420-4127 is suspended. Action Required!
SPF=FAIL
DKIM=FAIL
DMARC=FAIL

Dear Valued Customer,

Your parcel #8420-4127 failed to dispatch because of unpaid custom taxes of $4.99. 
We require immediate confirmation of physical storage records to secure package release.
Please login immediately on our premium web portal to coordinate verification:
http://premium-bonus-rewards.xyz/login.php

Please review the attached invoice breakdown within 24 hours to prevent immediate recycling.

[Attachment: dhl_release_invoice_payment.zip.exe]`
    },
    {
      title: "Secure Bank Social Engineering (Credential Leak)",
      filename: "secure_bank_alert.eml",
      content: `Received: from proxy-server.secure-bank-login-update.com (secure-bank-login-update.com [172.67.142.201])
From: Bank Security Services <security-notices@secure-bank-login-update.com>
Subject: Suspicious Login Alert: Confirm Your Active ID Immediately
Return-Path: admin@secure-bank-login-update.com
SPF=PASS
DKIM=NONE
DMARC=FAIL

Attention Customer,

A login attempt from unrecognized Tor Exit IP Address 185.220.101.5 was intercepted by our backend firewall.
If this was not you, please secure your checking and savings credentials immediately by confirming your multi-factor credentials:
http://dhl-tracking-delivery-panel.xyz/verify

Your access is temporarily frozen pending resolution of security credentials. Thank you.

[Attachment: bank_terms.pdf]`
    },
    {
      title: "Benign Corporate Workplace Briefing",
      filename: "corporate_newsletter.eml",
      content: `Received: from mail-sender.google.com (mail-sender.google.com [8.8.8.8])
From: Security Operations Center <admin-alert@google.com>
Subject: Monthly Security Assessment Checklist Consolidated
SPF=PASS
DKIM=PASS
DMARC=PASS

Hello All,

This is your monthly corporate security bulletin. Please complete the following items:
1. Revise active directory passwords older than 90 days.
2. Complete the phishing training video block inside portal.
3. Review global network proxy documentation: https://www.google.com/

No dynamic actions are required from endpoints. This is a secure automated message.

[Attachment: security_assessment_whitepaper.pdf]`
    }
  ];

  if (!currentUser || !token) {
    return <LoginView onLoginSuccess={(savedToken, savedUser) => {
      setToken(savedToken);
      setCurrentUser(savedUser);
    }} />;
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 flex overflow-hidden font-sans border-zinc-850 animate-fade-in" id="cyberlens_root">
      
      {/* Custom Toast Notification Overlay */}
      {toast && (
        <div className="fixed top-5 right-5 z-[9999] flex items-center gap-3 px-4 py-3 bg-[#0d0d11] border border-zinc-800 rounded-xl shadow-2xl animate-in slide-in-from-top-4 duration-300">
          <div className={`p-1.5 rounded-lg shrink-0 ${
            toast.type === "success" 
              ? "bg-emerald-500/10 text-emerald-400" 
              : toast.type === "error" 
                ? "bg-rose-500/10 text-rose-400" 
                : "bg-blue-500/10 text-blue-400"
          }`}>
            {toast.type === "success" ? <CheckCircle size={15} /> : (toast.type === "error" ? <AlertCircle size={15} /> : <Clock size={15} />)}
          </div>
          <span className="text-xs font-mono text-zinc-200 font-semibold">{toast.message}</span>
        </div>
      )}

      {/* Custom Confirmation Dialog Modal Overlay */}
      {confirmDialog && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-sm bg-[#0d0d11] border border-zinc-800 rounded-2xl p-6 shadow-2xl space-y-4 animate-in fade-in duration-200">
            <div className="flex items-start gap-3">
              <div className="p-2.5 bg-red-500/10 text-rose-400 rounded-xl border border-rose-950/50 shrink-0">
                <AlertCircle size={20} />
              </div>
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-slate-100 font-mono uppercase tracking-wide">{confirmDialog.title}</h4>
                <p className="text-[11px] text-zinc-400 leading-relaxed font-mono">
                  {confirmDialog.message}
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setConfirmDialog(null)}
                className="px-3.5 py-2 bg-zinc-900 hover:bg-zinc-850 text-zinc-400 hover:text-zinc-200 rounded-lg text-[11px] font-mono font-bold transition border border-zinc-800 cursor-pointer"
              >
                BATAL
              </button>
              <button
                type="button"
                onClick={() => {
                  confirmDialog.onConfirm();
                  setConfirmDialog(null);
                }}
                className="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-[11px] font-mono font-bold transition cursor-pointer flex items-center gap-1"
              >
                <Trash2 size={12} />
                PROSES
              </button>
            </div>
          </div>
        </div>
      )}

      
      {/* Dynamic Navigation Sidebar */}
      <nav id="cyberlens_sidebar" className="w-20 lg:w-64 border-r border-zinc-800 flex flex-col justify-between py-6 bg-[#0d0d0f] shrink-0">
        <div className="space-y-8">
          
          {/* Main Logo Header */}
          <div className="px-4 lg:px-6 flex items-center gap-3">
            <div className="w-12 h-12 bg-blue-600 hover:bg-blue-500 rounded-xl flex items-center justify-center shadow-lg shadow-blue-950/40 shrink-0 transition duration-300">
              <ShieldAlert className="text-white text-xl" size={24} />
            </div>
            <div className="hidden lg:block">
              <h1 className="text-lg font-bold tracking-tight font-display text-white">CyberLens</h1>
              <span className="text-[10px] text-zinc-500 font-mono tracking-widest block uppercase">SOC INVESTIGATOR</span>
            </div>
          </div>

          {/* Navigation Items */}
          <div className="px-3 space-y-1.5" id="navigation_items">
            <button
              onClick={() => setActiveTab("dashboard")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                activeTab === "dashboard"
                  ? "bg-blue-600/10 text-blue-400 border-l-2 border-blue-500"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40"
              }`}
            >
              <Cpu size={18} />
              <span className="hidden lg:inline font-display">Dashboard Feed</span>
            </button>

            <button
              onClick={() => setActiveTab("lookup")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                activeTab === "lookup"
                  ? "bg-blue-600/10 text-blue-400 border-l-2 border-blue-500"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40"
              }`}
            >
              <Search size={18} />
              <span className="hidden lg:inline font-display">IOC Threat Lookup</span>
            </button>

            <button
              onClick={() => setActiveTab("email")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                activeTab === "email"
                  ? "bg-blue-600/10 text-blue-400 border-l-2 border-blue-500"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40"
              }`}
            >
              <Mail size={18} />
              <span className="hidden lg:inline font-display">Phishing Analyzer</span>
            </button>

            <button
              onClick={() => setActiveTab("logs")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                activeTab === "logs"
                  ? "bg-blue-600/10 text-blue-400 border-l-2 border-blue-500"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40"
              }`}
            >
              <History size={18} />
              <span className="hidden lg:inline font-display">Reports & History</span>
            </button>

            {/* Admin Specific Tabs */}
            {currentUser?.role === "Admin" && (
              <>
                <div className="pt-4 pb-1 hidden lg:block border-t border-zinc-805/40 border-zinc-800/40 my-2">
                  <span className="px-4 text-[10px] text-zinc-500 font-mono tracking-widest block uppercase font-bold">ADMINISTRATION</span>
                </div>
                
                <button
                  onClick={() => setActiveTab("users" as any)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                    activeTab === ("users" as any)
                      ? "bg-blue-600/10 text-blue-400 border-l-2 border-blue-500"
                      : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40"
                  }`}
                >
                  <Users size={18} />
                  <span className="hidden lg:inline font-display">User Management</span>
                </button>

                <button
                  onClick={() => setActiveTab("integrations" as any)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                    activeTab === ("integrations" as any)
                      ? "bg-blue-600/10 text-blue-400 border-l-2 border-blue-500"
                      : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40"
                  }`}
                >
                  <Settings size={18} />
                  <span className="hidden lg:inline font-display">Integration Settings</span>
                </button>

                <button
                  onClick={() => setActiveTab("auditLogs" as any)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                    activeTab === ("auditLogs" as any)
                      ? "bg-blue-600/10 text-blue-400 border-l-2 border-blue-500"
                      : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40"
                  }`}
                >
                  <ClipboardList size={18} />
                  <span className="hidden lg:inline font-display">System Audit Logs</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Sidebar Footer Info */}
        <div className="px-4 py-4 border-t border-zinc-800/60 hidden lg:block text-xs font-mono text-zinc-500 space-y-2">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>API Proxy Layer: Active</span>
          </div>
          <div>Version v2.1.0-SOC</div>
          
          <div className="pt-2">
            <button
              onClick={() => {
                setChangePasswordError(null);
                setChangePasswordSuccess(null);
                setShowPasswordChange(prev => !prev);
              }}
              className="text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5 hover:underline font-bold"
            >
              <KeyRound size={12} className="text-zinc-500 animate-pulse" />
              Ubah Sandi Sesi
            </button>
          </div>

          {showPasswordChange && (
            <form onSubmit={handleChangePasswordSubmit} className="mt-4 p-3 bg-zinc-950 border border-zinc-850 rounded-lg space-y-2.5 font-mono text-[11px] animate-fadeIn">
              <span className="text-[10px] text-zinc-400 font-bold block uppercase border-b border-zinc-900 pb-1">Ubah Sandi Sesi</span>
              
              <div className="space-y-1">
                <span className="text-zinc-500">Sandi Saat Ini:</span>
                <input
                  type="password"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-805 border-zinc-800 rounded px-2 py-1 text-xs text-white"
                  placeholder="Sandi lama"
                />
              </div>

              <div className="space-y-1">
                <span className="text-zinc-500">Sandi Baru:</span>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-805 border-zinc-800 rounded px-2 py-1 text-xs text-white"
                  placeholder="Sandi baru"
                />
              </div>

              {changePasswordError && <span className="text-rose-400 block font-semibold leading-normal">{changePasswordError}</span>}
              {changePasswordSuccess && <span className="text-emerald-400 block font-semibold leading-normal">{changePasswordSuccess}</span>}

              <button
                type="submit"
                disabled={changingPassword}
                className="w-full py-1 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded cursor-pointer transition text-[10px]"
              >
                {changingPassword ? "Menyimpan..." : "Update Sandi"}
              </button>
            </form>
          )}
        </div>
      </nav>

      {/* Main Content Pane */}
      <div className="flex-1 flex flex-col min-w-0" id="main_pane">
        
        {/* Top Header Bar */}
        <header className="h-16 border-b border-zinc-800 px-6 flex items-center justify-between bg-[#0c0c0e]">
          <div className="flex items-center gap-4">
            <span className="text-zinc-500 font-medium text-sm tracking-wide uppercase font-display">Investigation Status</span>
            <span className="text-zinc-700 font-mono">/</span>
            <span className="text-zinc-300 font-mono text-xs bg-zinc-900/80 px-2.5 py-0.5 rounded border border-zinc-800 select-all flex items-center gap-1.5 leading-none">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse"></span>
              Sesi: {currentUser.username} ({currentUser.role})
            </span>
          </div>
          
          <div className="flex items-center gap-3">
            <div className="bg-zinc-900/80 border border-zinc-805 border-zinc-800 rounded-full px-3 py-1 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-tighter">Ollama Local: Llama3 Running</span>
            </div>
            
            <button
              onClick={handleLogout}
              className="px-3.5 py-1.5 bg-red-950/20 hover:bg-red-950/50 text-rose-400 border border-red-900/35 rounded-lg text-xs font-semibold cursor-pointer flex items-center gap-1.5 tracking-tight transition"
              id="sidebar_sign_out_btn"
            >
              <LogOut size={13} />
              Sign Out
            </button>
          </div>
        </header>

        {/* Main Work Area Container */}
        <main className="flex-1 p-6 overflow-y-auto space-y-6">
          
          {/* TAB 1: DASHBOARD FEED */}
          {activeTab === "dashboard" && (
            <DashboardView 
              records={records}
              onSelectRecord={handleSelectRecord}
              onNavigateToLookup={() => setActiveTab("lookup")}
              onNavigateToEmail={() => setActiveTab("email")}
              token={token}
            />
          )}

          {/* TAB 2: IOC LOOKUP SYSTEM */}
          {activeTab === "lookup" && (
            <div id="lookup_section" className="space-y-6">
              
              {/* Quick Search and suggestion banner */}
              <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6">
                <h2 className="text-lg font-bold text-slate-100 font-display mb-1">Global Threat Intelligence Parser</h2>
                <p className="text-sm text-zinc-400 mb-6">
                  Masukkan IP Address, Domain, URL, atau Hash untuk memulai investigasi Threat Intelligence.
                </p>

                <form onSubmit={handleIOCSearchSubmit} className="flex flex-col md:flex-row gap-3">
                  <div className="flex-1 relative">
                    <span className="absolute inset-y-0 left-0 flex items-center pl-3.5 text-zinc-500">
                      <Search size={18} />
                    </span>
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Contoh: 185.220.101.5, secure-bank-login-update.com, atau Hash MD5 WannaCry"
                      className="w-full bg-zinc-950/80 border border-zinc-800 rounded-xl pl-11 pr-4 py-3 text-sm font-mono text-slate-100 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-medium transition duration-200 disabled:opacity-50 shrink-0 cursor-pointer flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="animate-spin" size={16} />
                        Querying Registries...
                      </>
                    ) : (
                      <>
                        <Zap size={16} />
                        Investigate IOC
                      </>
                    )}
                  </button>
                </form>

                {/* Simulated Playground helper nodes */}
                <div className="mt-4 pt-4 border-t border-zinc-800/50">
                  <span className="text-xs text-zinc-500 font-mono block mb-2 font-semibold">CHOOSE AN IOC TEMPLATE FOR INVESTIGATION DEMO:</span>
                  <div className="flex flex-wrap gap-2">
                    <button 
                      onClick={() => handleIOCOnceSet("185.220.101.5")}
                      className="text-xs bg-red-950/30 hover:bg-red-950/60 border border-red-900/30 text-rose-400 px-3 py-1 rounded-md font-mono transition"
                    >
                      IP: Tor Exit (185.220.101.5)
                    </button>
                    <button 
                      onClick={() => handleIOCOnceSet("secure-bank-login-update.com")}
                      className="text-xs bg-red-950/30 hover:bg-red-950/60 border border-red-900/30 text-rose-400 px-3 py-1 rounded-md font-mono transition"
                    >
                      Domain: secure-bank-login-update.com
                    </button>
                    <button 
                      onClick={() => handleIOCOnceSet("e2fc714c4727ee9395f3aba42badc0cd")}
                      className="text-xs bg-rose-950/30 hover:bg-rose-950/60 border border-red-900/30 text-rose-400 px-3 py-1 rounded-md font-mono transition"
                    >
                      Hash: WannaCry Ransomware
                    </button>
                    <button 
                      onClick={() => handleIOCOnceSet("8.8.8.8")}
                      className="text-xs bg-emerald-950/20 hover:bg-emerald-950/40 border border-emerald-900/30 text-emerald-400 px-3 py-1 rounded-md font-mono transition"
                    >
                      Benign IP: 8.8.8.8
                    </button>
                  </div>
                </div>
              </div>

              {/* Error prompt */}
              {error && (
                <div className="p-4 bg-red-950/30 border border-red-900 text-rose-400 rounded-xl text-sm flex items-center gap-3">
                  <XCircle size={18} className="shrink-0" />
                  <div>{error}</div>
                </div>
              )}

              {/* SKELETON LOADER */}
              {loading && (
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 animate-pulse">
                  <div className="xl:col-span-8 space-y-6">
                    <div className="bg-zinc-900/20 border border-zinc-800/40 rounded-xl h-48"></div>
                    <div className="bg-zinc-900/20 border border-zinc-800/40 rounded-xl h-64"></div>
                  </div>
                  <div className="xl:col-span-4 space-y-6">
                    <div className="bg-zinc-900/20 border border-zinc-800/40 rounded-xl h-64"></div>
                    <div className="bg-zinc-900/20 border border-zinc-800/40 rounded-xl h-80"></div>
                  </div>
                </div>
              )}

              {/* RESULTS PANEL */}
              {selectedRecord && !loading && (
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-6" id="lookup_results">
                  
                  {/* Left Results Column */}
                  <div className="xl:col-span-8 space-y-6">
                    
                    {/* Diagnostic Summary Header */}
                    <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6">
                      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6 border-b border-zinc-800/80 pb-4">
                        <div>
                          <div className="flex items-center gap-3">
                            <span className="p-1.5 bg-blue-500/10 text-blue-400 rounded">
                              {selectedRecord.type === "IP" && <Globe size={18} />}
                              {selectedRecord.type === "DOMAIN" && <Globe size={18} />}
                              {selectedRecord.type === "URL" && <Link2 size={18} />}
                              {selectedRecord.type === "HASH" && <Hash size={18} />}
                            </span>
                            <span className="text-xs uppercase tracking-widest text-zinc-500 font-mono">
                              {selectedRecord.type} INDICATOR REPORT
                            </span>
                          </div>
                          <h1 className="text-2xl font-bold font-display text-white mt-1 select-all">
                            {selectedRecord.ioc}
                          </h1>
                        </div>

                        <div className="text-left md:text-right">
                          <span className="text-xs text-zinc-500 block uppercase font-mono tracking-wider">Scan Time (UTC)</span>
                          <span className="text-sm font-mono text-zinc-300">
                            {new Date(selectedRecord.timestamp).toLocaleDateString()} {new Date(selectedRecord.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>

                      {/* Diagnostic score metrics rows */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        {/* 1. AbuseIPDB Card */}
                        <div className="bg-zinc-950/60 p-4 border border-zinc-800/60 rounded-xl">
                          <span className="text-[10px] text-zinc-500 uppercase font-mono block mb-1">AbuseIPDB Score</span>
                          {selectedRecord.type === "IP" && selectedRecord.threatIntel?.abuseScore !== undefined ? (
                            <span className={`text-xl font-mono font-bold ${selectedRecord.threatIntel.abuseScore > 50 ? 'text-rose-500' : 'text-emerald-400'}`}>
                              {selectedRecord.threatIntel.abuseScore}%
                            </span>
                          ) : (
                            <span className="text-xl font-mono font-bold text-zinc-500">-</span>
                          )}
                          <span className="text-[10px] text-zinc-600 block mt-1 font-mono">Skor probabilitas aktivitas penyalahgunaan (abuse).</span>
                        </div>

                        {/* 2. VirusTotal Card */}
                        <div className="bg-zinc-950/60 p-4 border border-zinc-800/60 rounded-xl">
                          <span className="text-[10px] text-zinc-500 uppercase font-mono block mb-1">VirusTotal Ratio</span>
                          {selectedRecord.threatIntel?.vtMalicious !== undefined && selectedRecord.threatIntel?.vtTotal !== undefined ? (
                            <span className={`text-xl font-mono font-bold ${selectedRecord.threatIntel.vtMalicious > 0 ? 'text-rose-500' : 'text-emerald-400'}`}>
                              {selectedRecord.threatIntel.vtMalicious} / {selectedRecord.threatIntel.vtTotal}
                            </span>
                          ) : (
                            <span className="text-xl font-mono font-bold text-zinc-500">-</span>
                          )}
                          <span className="text-[10px] text-zinc-600 block mt-1 font-mono">Jumlah engine keamanan yang mendeteksi ancaman berkas.</span>
                        </div>

                        {/* 3. AlienVault OTX Card */}
                        <div className="bg-zinc-950/60 p-4 border border-zinc-800/60 rounded-xl">
                          <span className="text-[10px] text-zinc-500 uppercase font-mono block mb-1">AlienVault OTX</span>
                          {selectedRecord.threatIntel?.otxPulseCount !== undefined ? (
                            <span className={`text-xl font-mono font-bold ${selectedRecord.threatIntel.otxPulseCount > 0 ? 'text-rose-500' : 'text-emerald-400'}`}>
                              {selectedRecord.threatIntel.otxPulseCount} Pulses
                            </span>
                          ) : (
                            <span className="text-xl font-mono font-bold text-zinc-500">-</span>
                          )}
                          <span className="text-[10px] text-zinc-600 block mt-1 font-mono">Total pulse ancaman yang terdaftar pada komunitas AlienVault OTX.</span>
                        </div>

                        {/* 4. Threat Registry Card depending on IOC Type */}
                        <div className="bg-zinc-950/60 p-4 border border-zinc-800/60 rounded-xl">
                          {selectedRecord.type === "HASH" ? (
                            <>
                              <span className="text-[10px] text-zinc-500 uppercase font-mono block mb-1">MalwareBazaar Registry</span>
                              {selectedRecord.threatIntel?.malwareBazaarMatch !== undefined ? (
                                <span className={`text-xl font-mono font-bold ${selectedRecord.threatIntel.malwareBazaarMatch ? "text-rose-500" : "text-emerald-400"}`}>
                                  {selectedRecord.threatIntel.malwareBazaarMatch ? "HIT" : "CLEAN"}
                                </span>
                              ) : (
                                <span className="text-xl font-mono font-bold text-zinc-500">-</span>
                              )}
                              <span className="text-[10px] text-zinc-600 block mt-1 font-mono">Kecocokan malware signature aktif pada database MalwareBazaar.</span>
                            </>
                          ) : selectedRecord.type === "URL" || selectedRecord.type === "DOMAIN" ? (
                            <>
                              <span className="text-[10px] text-zinc-500 uppercase font-mono block mb-1">URLHaus Registry</span>
                              {selectedRecord.threatIntel?.urlhausDetection !== undefined ? (
                                <span className={`text-xl font-mono font-bold ${selectedRecord.threatIntel.urlhausDetection ? "text-rose-500" : "text-emerald-400"}`}>
                                  {selectedRecord.threatIntel.urlhausDetection ? "HIT" : "CLEAN"}
                                </span>
                              ) : (
                                <span className="text-xl font-mono font-bold text-zinc-500">-</span>
                              )}
                              <span className="text-[10px] text-zinc-600 block mt-1 font-mono">Kecocokan indikator malware aktif pada database URLHaus.</span>
                            </>
                          ) : (
                            <>
                              <span className="text-[10px] text-zinc-500 uppercase font-mono block mb-1">Threat Registry</span>
                              <span className="text-xl font-mono font-bold text-zinc-500">-</span>
                              <span className="text-[10px] text-zinc-600 block mt-1 font-mono">Database reputasi registry tidak berlaku untuk tipe IOC ini.</span>
                            </>
                          )}
                        </div>
                      </div>

                      {/* Detail attributes table */}
                      <div className="mt-6 pt-6 border-t border-zinc-800/60 space-y-3">
                        <h4 className="text-xs font-mono font-bold text-zinc-400 uppercase tracking-widest">Metadata Indicators</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                          <div className="flex justify-between p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                            <span className="text-zinc-500">Reputation Status:</span>
                            <span className={`font-semibold ${
                              selectedRecord.threatIntel?.reputation === "Malicious" ? "text-rose-400 font-bold" :
                              selectedRecord.threatIntel?.reputation === "Suspicious" ? "text-amber-400 font-bold" :
                              selectedRecord.threatIntel?.reputation === "Clean" ? "text-emerald-400 font-semibold" :
                              selectedRecord.threatIntel?.reputation === "Conflicting Intelligence Sources" ? "text-purple-400 font-bold" :
                              "text-zinc-400 font-semibold"
                            }`}>{selectedRecord.threatIntel?.reputation || "Unknown"}</span>
                          </div>
                          {selectedRecord.threatIntel?.reputation === "Conflicting Intelligence Sources" && selectedRecord.threatIntel.conflictingSources && (
                            <div className="p-3 bg-purple-500/10 rounded border border-purple-500/30 col-span-2 text-purple-300">
                              <div className="font-bold flex items-center gap-1.5 mb-1.5">
                                <span className="inline-block w-2.5 h-2.5 rounded-full bg-purple-500 animate-pulse"></span>
                                Detail Konflik Sumber Intelijen:
                              </div>
                              <ul className="list-disc list-inside space-y-1.5 pl-1.5 font-mono text-[11px] text-zinc-350">
                                {selectedRecord.threatIntel.conflictingSources.map((source: string) => (
                                  <li key={source}>{source}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                          {selectedRecord.threatIntel?.country && (
                            <div className="flex justify-between p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                              <span className="text-zinc-500">Country of Origin:</span>
                              <span className="text-zinc-300 font-semibold">{selectedRecord.threatIntel.country} {selectedRecord.threatIntel.countryCode && `(${selectedRecord.threatIntel.countryCode})`}</span>
                            </div>
                          )}
                          {selectedRecord.threatIntel?.organization && (
                            <div className="flex justify-between p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                              <span className="text-zinc-500">Autonomous System / Organization:</span>
                              <span className="text-zinc-300 font-semibold truncate max-w-[180px]">{selectedRecord.threatIntel.organization}</span>
                            </div>
                          )}
                          {selectedRecord.threatIntel?.asn && (
                            <div className="flex justify-between p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                              <span className="text-zinc-500">ASN System:</span>
                              <span className="text-zinc-300 font-semibold">{selectedRecord.threatIntel.asn}</span>
                            </div>
                          )}
                          {selectedRecord.threatIntel?.domainAge && (
                            <div className="flex justify-between p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                              <span className="text-zinc-500">Domain Age:</span>
                              <span className="text-zinc-300 font-semibold text-rose-400">{selectedRecord.threatIntel.domainAge}</span>
                            </div>
                          )}
                          {selectedRecord.threatIntel?.malwareFamily && (
                            <div className="flex justify-between p-2.5 bg-[#ef4444]/10 rounded border border-[#ef4444]/20 col-span-2">
                              <span className="text-rose-400 font-bold">Malware Family:</span>
                              <span className="text-rose-300 font-mono font-bold">{selectedRecord.threatIntel.malwareFamily}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Threat Intelligence provider findings table */}
                    {selectedRecord.type === "DOMAIN" && (
                      <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl overflow-hidden">
                        <div className="px-6 py-4 border-b border-zinc-800 bg-zinc-900/20">
                          <h2 className="text-sm font-semibold uppercase tracking-widest text-zinc-400 font-display">Infrastructure Analysis</h2>
                          <div className="mt-1.5 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4 text-[11px] font-mono text-zinc-500">
                            <span className="flex items-center gap-1.5">
                              <span className="w-1 h-1 rounded-full bg-zinc-700"></span>
                              DNS records
                            </span>
                            <span className="flex items-center gap-1.5">
                              <span className="w-1 h-1 rounded-full bg-zinc-700"></span>
                              Mail routing information
                            </span>
                            <span className="flex items-center gap-1.5">
                              <span className="w-1 h-1 rounded-full bg-zinc-700"></span>
                              Domain infrastructure details.
                            </span>
                          </div>
                        </div>
                        
                        <div className="p-6 space-y-4">
                          {selectedRecord.threatIntel?.dnsInfo ? (
                            <div className="space-y-3 font-mono text-xs">
                              <div className="p-3 bg-zinc-950/60 rounded-lg border border-zinc-850 space-y-1.5">
                                <span className="text-blue-400 font-semibold">DNS A Record (IP Mapping):</span>
                                <div className="text-zinc-300 space-y-1 pl-3 border-l border-zinc-800">
                                  {selectedRecord.threatIntel.dnsInfo.a?.map((ip: string) => (
                                    <div key={ip} className="flex items-center gap-2">
                                      <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
                                      {ip}
                                    </div>
                                  )) || "No active A mappings resolved"}
                                </div>
                              </div>

                              <div className="p-3 bg-zinc-950/60 rounded-lg border border-zinc-850 space-y-1.5">
                                <span className="text-amber-400 font-semibold">DNS MX Record (Mail Routing Offset):</span>
                                <div className="text-zinc-300 space-y-1 pl-3 border-l border-zinc-800">
                                  {selectedRecord.threatIntel.dnsInfo.mx?.map((mx: string) => (
                                    <div key={mx} className="flex items-center gap-2">
                                      <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                                      {mx}
                                    </div>
                                  )) || "No active MX records resolved"}
                                </div>
                              </div>

                              <div className="p-3 bg-zinc-950/60 rounded-lg border border-zinc-850 space-y-1.5">
                                <span className="text-indigo-400 font-semibold">DNS TXT Record (SPF Authentication):</span>
                                <div className="text-zinc-300 space-y-1 pl-3 border-l border-zinc-800 truncate">
                                  {selectedRecord.threatIntel.dnsInfo.txt?.map((txt: string) => (
                                    <div key={txt} className="flex items-center gap-2">
                                      <span className="w-1.5 h-1.5 rounded-full bg-indigo-500"></span>
                                      {txt}
                                    </div>
                                  )) || "No TXT descriptors active"}
                                </div>
                              </div>
                            </div>
                          ) : (
                            <div className="text-xs font-mono text-zinc-500 italic py-6 text-center">
                              {selectedRecord.type === 'HASH' 
                                ? "Indikator ini adalah berkas checksum statis. Informasi DNS lookup tidak tersedia untuk indikator Hash." 
                                : "DNS lookup tidak diperlukan untuk indikator ini. Informasi detail berhasil diidentifikasi dari basis data threat intelligence."
                              }
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Right Column: Risk scoring metric and Action Checklist */}
                  <div className="xl:col-span-4 space-y-6">
                    
                    {/* Gauge circle rating */}
                    <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6 flex flex-col items-center justify-center">
                      <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 mb-6 font-display text-center">Engine Risk Assessment</h3>
                      
                      <div className="relative flex items-center justify-center mb-5">
                        <svg className="w-40 h-40 transform -rotate-90">
                          <circle cx="80" cy="80" r="70" stroke="#18181b" strokeWidth="12" fill="transparent" />
                          <circle 
                            cx="80" 
                            cy="80" 
                            r="70" 
                            stroke={
                              selectedRecord.severity === "Critical" || selectedRecord.severity === "High" 
                                ? "#ef4444" 
                                : selectedRecord.severity === "Medium" 
                                  ? "#f59e0b" 
                                  : "#10b981"
                            } 
                            strokeWidth="12" 
                            fill="transparent" 
                            strokeDasharray="440" 
                            strokeDashoffset={440 - (440 * selectedRecord.riskScore) / 100} 
                            className="transition-all duration-1000 ease-out"
                          />
                        </svg>
                        
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <span className={`text-4xl font-black font-display ${
                            selectedRecord.severity === "Critical" || selectedRecord.severity === "High" 
                              ? "text-rose-500" 
                              : selectedRecord.severity === "Medium" 
                                ? "text-amber-400" 
                                : "text-emerald-400"
                          }`}>
                            {selectedRecord.riskScore}
                          </span>
                          <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest font-mono mt-0.5">SCORE</span>
                        </div>
                      </div>

                      <div className={`px-5 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                        selectedRecord.severity === "Critical" || selectedRecord.severity === "High"
                          ? "bg-rose-950/40 text-rose-400 border-rose-900/40"
                          : selectedRecord.severity === "Medium"
                            ? "bg-amber-950/40 text-amber-400 border-amber-900/40"
                            : "bg-emerald-950/20 text-emerald-400 border-emerald-900/30"
                      }`}>
                        Severity: {selectedRecord.severity}
                      </div>

                      {/* Display score reasons */}
                      <div className="mt-6 pt-6 border-t border-zinc-800/60 w-full">
                        <span className="text-[10px] font-mono uppercase text-zinc-500 font-bold block mb-3">Risk Factors:</span>
                        <ul className="space-y-2 text-xs font-mono text-zinc-400 pl-1">
                          {selectedRecord.reasons?.map((reason, idx) => (
                            <li key={idx} className="flex gap-2 text-slate-300">
                              <span className="text-rose-500 font-bold shrink-0">▪</span>
                              <span>{reason}</span>
                            </li>
                          )) || <li className="italic text-zinc-500 text-[11px]">Tidak ada Risk Factors berbahaya yang terdeteksi untuk indikator ini.</li>}
                        </ul>
                      </div>
                    </div>

                    {/* Forensic Insight Card */}
                    <div className="bg-blue-600/5 border border-blue-500/20 rounded-xl p-6 flex-1 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-blue-900/20">
                          <span className="w-6 h-6 rounded bg-blue-500/10 flex items-center justify-center font-bold text-xs text-blue-400">
                            CL
                          </span>
                          <h3 className="text-sm font-bold text-blue-200 font-display">CyberLens analytical summary</h3>
                        </div>

                        <div className="space-y-4">
                          <div>
                            <span className="text-[9px] font-mono tracking-widest text-zinc-500 uppercase block font-bold">Investigation Summary</span>
                            <p className="text-xs text-zinc-300 leading-relaxed mt-1 italic select-all">
                              "{selectedRecord.aiSummary?.investigationSummary || "The IOC is undergoing analytical synthesis of host logs."}"
                            </p>
                          </div>

                          <div>
                            <span className="text-[9px] font-mono tracking-widest text-zinc-500 uppercase block font-bold">Threat Assessment</span>
                            <p className="text-xs text-zinc-300 leading-relaxed mt-1">
                              {selectedRecord.aiSummary?.threatAssessment || "Evaluation pending automated database replication."}
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="mt-6 pt-5 border-t border-blue-950/40">
                        <span className="text-[10px] font-mono uppercase text-zinc-500 font-bold block mb-3">Incident Response Playbook:</span>
                        <div className="space-y-2">
                          {selectedRecord.aiSummary?.recommendedActions?.map((act, index) => (
                            <div key={index} className="flex items-start gap-2.5 text-xs text-zinc-300 bg-zinc-950/40 p-2 rounded border border-zinc-850 select-all">
                              <span className="p-0.5 bg-blue-500/15 text-blue-400 rounded mt-0.5 font-bold font-mono text-[9px] w-4 h-4 flex items-center justify-center">
                                {index + 1}
                              </span>
                              <span className="leading-snug">{act}</span>
                            </div>
                          )) || (
                            <div className="text-xs italic text-zinc-500">Pantau log sistem secara berkelanjutan untuk mendeteksi aktivitas mencurigakan lainnya.</div>
                          )}
                        </div>

                        {/* Export reports utility button */}
                        <button 
                          onClick={() => handleExportIncidentPDF(selectedRecord)}
                          className="w-full mt-6 bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-xl text-xs font-bold tracking-wider transition-all border border-blue-700/50 flex items-center justify-center gap-2 cursor-pointer shadow-md shadow-blue-900/10"
                        >
                          <Download size={14} />
                          EXPORT INCIDENT REPORT (PDF)
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: PHISHING EMAIL FORENSICS */}
          {activeTab === "email" && (
            <div id="email_analyzer_section" className="space-y-6">
              
              <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6">
                <h2 className="text-lg font-bold text-slate-100 font-display mb-1">Interactive Phishing Email Analyzer (EML)</h2>
                <p className="text-sm text-zinc-400 mb-6 font-medium">
                  Lakukan ekstraksi parameter Email Header, status autentikasi protokol keamanan (SPF, DKIM, DMARC), file Attachment yang tersemat, serta Phishing URL berbahaya secara instan.
                </p>

                {/* Prebuilt template select section */}
                <div className="space-y-3 mb-6 bg-zinc-950/40 p-4 rounded-xl border border-zinc-800/60">
                  <span className="text-xs font-mono font-semibold text-zinc-400 tracking-wide block">CHOOSE A PRECONFIGURED PHISHING EMAIL TEMPLATE:</span>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {SPAM_TEMPLATES.map((tpl, i) => (
                      <button
                        key={i}
                        onClick={() => {
                          setEmailRawInput(tpl.content);
                          setUploadedFilename(tpl.filename);
                        }}
                        className={`text-left p-3 rounded-lg border text-xs font-mono transition justify-between flex flex-col gap-2 ${
                          uploadedFilename === tpl.filename 
                            ? "bg-blue-600/10 border-blue-500/50 text-blue-300"
                            : "bg-zinc-900/80 hover:bg-zinc-800/80 border-zinc-800 text-zinc-400"
                        }`}
                      >
                        <div className="font-semibold block truncate">{tpl.title}</div>
                        <div className="text-[10px] text-zinc-500 flex items-center gap-1">
                          <FileText size={12} /> {tpl.filename}
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Main Raw Input box */}
                <div className="space-y-3">
                  <label className="text-xs font-mono text-zinc-400 font-bold uppercase tracking-wider block">RAW EML EMAIL CONTENT (HEADERS + BODY):</label>
                  <textarea
                    value={emailRawInput}
                    onChange={(e) => setEmailRawInput(e.target.value)}
                    rows={12}
                    placeholder="Tempel teks mentah EML beserta header lengkap dan konten body email di sini..."
                    className="w-full bg-zinc-950 text-xs font-mono p-4 border border-zinc-800 rounded-xl placeholder:text-zinc-600 font-medium focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                  
                  <div className="flex justify-between items-center flex-wrap gap-3">
                    <div className="flex items-center gap-2 text-xs font-mono text-zinc-500">
                      <span>Filename:</span>
                      <input 
                        type="text" 
                        value={uploadedFilename} 
                        onChange={(e) => setUploadedFilename(e.target.value)}
                        className="bg-zinc-900 px-2 py-0.5 rounded border border-zinc-800/70 text-zinc-300" 
                      />
                    </div>
                    
                    <button
                      onClick={() => handleEmailAnalyzeSubmit()}
                      disabled={analyzingEmail || !emailRawInput.trim()}
                      className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-semibold transition cursor-pointer flex items-center gap-2' disabled:opacity-40"
                    >
                      {analyzingEmail ? (
                        <>
                          <RefreshCw className="animate-spin" size={16} />
                          Running Header Diagnostics...
                        </>
                      ) : (
                        <>
                          <Terminal size={16} />
                          Parse & Analyze EML File
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* EMAIL ANALYSIS RESULTS */}
              {emailAnalysisResult && (
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 animate-fadeIn" id="email_results_container">
                  
                  {/* Left Forensic details */}
                  <div className="xl:col-span-8 space-y-6">
                    
                    {/* Headers card visual */}
                    <div className="bg-cyber-card border border-zinc-800 rounded-xl p-6">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-500 mb-4 font-mono border-b border-zinc-800 pb-2">
                        Envelope Header Diagnostics
                      </h3>

                      <div className="grid grid-cols-1 gap-3.5 font-mono text-xs text-zinc-300">
                        <div className="grid grid-cols-12 p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                          <span className="col-span-3 text-zinc-500 font-semibold uppercase">Subjek:</span>
                          <span className="col-span-9 text-slate-100 font-bold select-all">{emailAnalysisResult.subject}</span>
                        </div>
                        <div className="grid grid-cols-12 p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                          <span className="col-span-3 text-zinc-500 font-semibold uppercase">Header Pengirim:</span>
                          <span className="col-span-9 text-slate-300 select-all">{emailAnalysisResult.headers?.from}</span>
                        </div>
                        <div className="grid grid-cols-12 p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                          <span className="col-span-3 text-zinc-500 font-semibold uppercase">Alamat Reply-To:</span>
                          <span className="col-span-9 text-slate-300 italic select-all">{emailAnalysisResult.headers?.replyTo}</span>
                        </div>
                        <div className="grid grid-cols-12 p-2.5 bg-zinc-950/40 rounded border border-zinc-850">
                          <span className="col-span-3 text-zinc-500 font-semibold uppercase">Return-Path:</span>
                          <span className="col-span-9 text-slate-300 select-all">{emailAnalysisResult.headers?.returnPath}</span>
                        </div>
                      </div>

                      {/* Path chain visual diagram */}
                      <div className="mt-6 pt-6 border-t border-zinc-800/80">
                        <span className="text-xs font-mono font-bold text-zinc-400 uppercase tracking-widest block mb-4">SMTP Delivery Chain Logs</span>
                        <div className="space-y-3.5 font-mono text-xs pl-2">
                          <div className="flex items-start gap-4">
                            <span className="p-1 px-1.5 bg-zinc-900 border border-zinc-800 rounded font-bold text-[10px] text-zinc-500">Node 2</span>
                            <div className="space-y-1">
                              <span className="text-zinc-300 block">relay-host-ingress.company-firewall.com [172.16.5.42]</span>
                              <span className="text-[10px] text-zinc-500">Diproses oleh relai penyaringan filter email SMTP internal.</span>
                            </div>
                          </div>
                          
                          <div className="h-6 w-0.5 bg-zinc-800 ml-6 border-l border-dashed border-zinc-700"></div>

                          <div className="flex items-start gap-4">
                            <span className="p-1 px-1.5 bg-red-950/30 border border-red-900/40 rounded font-bold text-[10px] text-rose-400">Node 1</span>
                            <div className="space-y-1">
                              <span className="text-rose-400 block font-semibold">Origin Server Network (Origin Host)</span>
                              <span className="text-[10px] text-zinc-500 font-mono block">
                                Matches: {emailAnalysisResult.headers?.receivedChain?.[0] || "Log routing server tidak ditemukan pada header email."}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Authentication validation grid */}
                    <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-500 mb-4 font-mono">
                        SMTP Authentication Logs
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        
                        {/* SPF info */}
                        <div className={`p-4 rounded-xl border ${
                          emailAnalysisResult.auth.spf.status === 'PASS' 
                            ? "bg-emerald-950/20 border-emerald-900/40" 
                            : (emailAnalysisResult.auth.spf.status === 'FAIL' ? "bg-red-950/30 border-red-900/30" : "bg-zinc-950/60 border-zinc-800/60")
                        }`}>
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-[11px] font-mono uppercase font-bold text-zinc-400">SPF Authentication Status</span>
                            <span className={`text-[10px] px-2 py-0.5 rounded font-bold font-mono ${
                              emailAnalysisResult.auth.spf.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-rose-500'
                            }`}>
                              {emailAnalysisResult.auth.spf.status}
                            </span>
                          </div>
                          <p className="text-xs font-mono text-zinc-400 leading-snug">
                            {emailAnalysisResult.auth.spf.details}
                          </p>
                        </div>

                        {/* DKIM info */}
                        <div className={`p-4 rounded-xl border ${
                          emailAnalysisResult.auth.dkim.status === 'PASS' 
                            ? "bg-emerald-950/20 border-emerald-900/40" 
                            : (emailAnalysisResult.auth.dkim.status === 'FAIL' ? "bg-red-950/30 border-red-900/30" : "bg-zinc-950/60 border-zinc-800/60")
                        }`}>
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-[11px] font-mono uppercase font-bold text-zinc-400">DKIM Signature Status</span>
                            <span className={`text-[10px] px-2 py-0.5 rounded font-bold font-mono ${
                              emailAnalysisResult.auth.dkim.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-rose-500'
                            }`}>
                              {emailAnalysisResult.auth.dkim.status}
                            </span>
                          </div>
                          <p className="text-xs font-mono text-zinc-400 leading-snug">
                            {emailAnalysisResult.auth.dkim.details}
                          </p>
                        </div>

                        {/* DMARC info */}
                        <div className={`p-4 rounded-xl border ${
                          emailAnalysisResult.auth.dmarc.status === 'PASS' 
                            ? "bg-emerald-950/20 border-emerald-900/40" 
                            : (emailAnalysisResult.auth.dmarc.status === 'FAIL' ? "bg-red-950/30 border-red-900/30" : "bg-[#18181b]/65 border-zinc-800/60")
                        }`}>
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-[11px] font-mono uppercase font-bold text-zinc-400">DMARC Alignment Status</span>
                            <span className={`text-[10px] px-2 py-0.5 rounded font-bold font-mono ${
                              emailAnalysisResult.auth.dmarc.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-rose-500'
                            }`}>
                              {emailAnalysisResult.auth.dmarc.status}
                            </span>
                          </div>
                          <p className="text-xs font-mono text-zinc-400 leading-snug">
                            {emailAnalysisResult.auth.dmarc.details}
                          </p>
                        </div>

                      </div>
                    </div>

                    {/* Deep inspection sections URLs/Attachments */}
                    <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6 space-y-6">
                      
                      {/* URLs parsed table */}
                      <div>
                        <h4 className="text-xs font-mono font-bold text-zinc-400 uppercase tracking-widest mb-3">Extracted URL Targets ({emailAnalysisResult.urls?.length || 0})</h4>
                        {emailAnalysisResult.urls && emailAnalysisResult.urls.length > 0 ? (
                          <div className="border border-zinc-800/60 rounded-xl overflow-hidden font-mono text-xs">
                            <table className="w-full text-left">
                              <thead className="bg-[#0e0e11] text-zinc-500 border-b border-zinc-800/50">
                                <tr>
                                  <th className="p-3">Parsed URL</th>
                                  <th className="p-3">URLHaus Detection</th>
                                  <th className="p-3">Threat Context</th>
                                  <th className="p-3 text-right">Investigation</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-zinc-800/40">
                                {emailAnalysisResult.urls.map((u, i) => (
                                  <tr key={i} className="hover:bg-zinc-950/30">
                                    <td className="p-3 text-slate-200 select-all font-mono font-semibold max-w-[250px] truncate">{u.url}</td>
                                    <td className="p-3">
                                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${u.urlhausHit ? 'bg-red-500/10 text-rose-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
                                        {u.urlhausHit ? 'MALICIOUS MATCH' : 'CLEAN'}
                                      </span>
                                    </td>
                                    <td className="p-3 text-zinc-400">{u.urlscanStatus}</td>
                                    <td className="p-3 text-right">
                                      <button 
                                        onClick={() => {
                                          setSearchQuery(u.url);
                                          setActiveTab("lookup");
                                        }}
                                        className="text-[11px] text-blue-400 hover:underline hover:text-blue-300 font-bold"
                                      >
                                        Investigate URL
                                      </button>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <div className="p-4 bg-zinc-950/40 text-center italic text-zinc-500 rounded-xl border border-zinc-850">
                            Tidak ada objek URL aktif yang terdeteksi dalam body email.
                          </div>
                        )}
                      </div>

                      {/* Attachments parsed list */}
                      <div>
                        <h4 className="text-xs font-mono font-bold text-zinc-400 uppercase tracking-widest mb-3">Extracted File Attachments ({emailAnalysisResult.attachments?.length || 0})</h4>
                        {emailAnalysisResult.attachments && emailAnalysisResult.attachments.length > 0 ? (
                          <div className="space-y-3">
                            {emailAnalysisResult.attachments.map((att, i) => (
                              <div key={i} className="bg-zinc-950/60 rounded-xl border border-zinc-800/80 p-4 font-mono text-xs text-zinc-300 space-y-3">
                                
                                <div className="flex justify-between items-center bg-[#070a13] p-2.5 rounded border border-zinc-800">
                                  <div className="flex items-center gap-2">
                                    <FileText className="text-blue-400" size={16} />
                                    <span className="font-bold text-slate-100 select-all">{att.filename}</span>
                                    <span className="text-[10px] text-zinc-500">({att.size})</span>
                                  </div>
                                  
                                  <button 
                                    onClick={() => {
                                      setSearchQuery(att.sha256);
                                      setActiveTab("lookup");
                                    }}
                                    className="text-[11px] bg-red-950/40 text-rose-400 hover:bg-rose-950/60 border border-red-900/40 px-2.5 py-1 rounded"
                                  >
                                    Investigate MD5 Checksum
                                  </button>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[10px] text-zinc-500">
                                  <div className="truncate"><span className="text-zinc-400 font-semibold">MD5:</span> <span className="select-all">{att.md5}</span></div>
                                  <div className="truncate"><span className="text-zinc-400 font-semibold">SHA1:</span> <span className="select-all">{att.sha1}</span></div>
                                  <div className="truncate"><span className="text-zinc-400 font-semibold">SHA256:</span> <span className="select-all">{att.sha256}</span></div>
                                </div>

                                <div className="flex justify-between items-center text-[11px] pt-2 border-t border-zinc-900">
                                  <div className="flex items-center gap-2">
                                    <span className={`w-2 h-2 rounded-full ${att.malwareBazaarMatch ? 'bg-rose-500 animate-pulse' : 'bg-emerald-500'}`}></span>
                                    <span>MalwareBazaar Correlation:</span>
                                    <span className={`font-bold uppercase ${att.malwareBazaarMatch ? 'text-rose-400' : 'text-emerald-400'}`}>
                                      {att.malwareBazaarMatch ? `MATCHED FAMILY: ${att.malwareFamily}` : 'CLEAN'}
                                    </span>
                                  </div>
                                  <span className="text-zinc-500 text-[10px]">Teridentifikasi dalam {att.otxPulses} pulse ancaman aktif pada AlienVault OTX.</span>
                                </div>

                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="p-4 bg-zinc-950/40 text-center italic text-zinc-500 rounded-xl border border-zinc-850">
                            Tidak ada file lampiran yang ditemukan dalam header email.
                          </div>
                        )}
                      </div>

                    </div>
                  </div>

                  {/* Right Score panel */}
                  <div className="xl:col-span-4 space-y-6">
                    
                    {/* Gauge circle rating */}
                    <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6 flex flex-col items-center justify-center">
                      <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 mb-6 font-display text-center">Envelope Phishing Risk</h3>
                      
                      <div className="relative flex items-center justify-center mb-5">
                        <svg className="w-40 h-40 transform -rotate-90">
                          <circle cx="80" cy="80" r="70" stroke="#18181b" strokeWidth="12" fill="transparent" />
                          <circle 
                            cx="80" 
                            cy="80" 
                            r="70" 
                            stroke={
                              emailAnalysisResult.severity === "Critical" || emailAnalysisResult.severity === "High" 
                                ? "#ef4444" 
                                : "#f59e0b"
                            } 
                            strokeWidth="12" 
                            fill="transparent" 
                            strokeDasharray="440" 
                            strokeDashoffset={440 - (440 * emailAnalysisResult.riskScore) / 100} 
                            className="transition-all duration-1000 ease-out"
                          />
                        </svg>
                        
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <span className={`text-4xl font-black font-display ${
                            emailAnalysisResult.severity === "Critical" || emailAnalysisResult.severity === "High" 
                              ? "text-rose-500" 
                              : "text-amber-400"
                          }`}>
                            {emailAnalysisResult.riskScore}
                          </span>
                          <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest font-mono mt-0.5">SCORE</span>
                        </div>
                      </div>

                      <div className={`px-5 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                        emailAnalysisResult.severity === "Critical" || emailAnalysisResult.severity === "High"
                          ? "bg-rose-950/40 text-rose-400 border-rose-900/40"
                          : "bg-amber-950/40 text-amber-400 border-amber-900/40"
                      }`}>
                        SEVERITY: {emailAnalysisResult.severity}
                      </div>

                      {/* Score rules layout */}
                      <div className="mt-6 pt-6 border-t border-zinc-800/60 w-full">
                        <span className="text-[10px] font-mono uppercase text-zinc-500 font-bold block mb-3">Risk Factors:</span>
                        <ul className="space-y-2 text-xs font-mono text-zinc-400 pl-1">
                          {emailAnalysisResult.reasons?.map((reason, idx) => (
                            <li key={idx} className="flex gap-2">
                              <span className="text-rose-500 font-bold">▪</span>
                              <span>{reason}</span>
                            </li>
                          )) || <li className="italic text-zinc-500 text-[11px]">Tidak ada Risk Factors berbahaya terdeteksi untuk email ini.</li>}
                        </ul>
                      </div>
                    </div>

                    {/* SOC Summary Card */}
                    <div className="bg-blue-600/5 border border-blue-500/20 rounded-xl p-6 flex-1 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-blue-900/20">
                          <span className="w-6 h-6 rounded bg-blue-500/10 flex items-center justify-center font-bold text-xs text-blue-400">
                            CL
                          </span>
                          <h3 className="text-sm font-bold text-blue-200 font-display">Forensic Analyst Summary</h3>
                        </div>

                        <div className="space-y-4">
                          <div>
                            <span className="text-[9px] font-mono tracking-widest text-zinc-500 uppercase block font-bold">Heuristic Incident Assessment</span>
                            <p className="text-xs text-zinc-300 leading-relaxed mt-1 italic select-all">
                              "{emailAnalysisResult.aiSummary?.investigationSummary || "Diagnostic brief pending complete payload evaluation."}"
                            </p>
                          </div>

                          <div>
                            <span className="text-[9px] font-mono tracking-widest text-zinc-500 uppercase block font-bold">Threat Impact Assessment</span>
                            <p className="text-xs text-zinc-300 leading-relaxed mt-1">
                              {emailAnalysisResult.aiSummary?.threatAssessment || "Determining overall risk parameters."}
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="mt-6 pt-5 border-t border-blue-950/40">
                        <span className="text-[10px] font-mono uppercase text-zinc-500 font-bold block mb-3">Incident Response Playbook:</span>
                        <div className="space-y-2">
                          {emailAnalysisResult.aiSummary?.recommendedActions?.map((act, index) => (
                            <div key={index} className="flex items-start gap-2.5 text-xs text-zinc-300 bg-zinc-950/40 p-2 rounded border border-zinc-850 select-all">
                              <span className="p-0.5 bg-blue-500/15 text-blue-400 rounded mt-0.5 font-bold font-mono text-[9px] w-4 h-4 flex items-center justify-center">
                                {index + 1}
                              </span>
                              <span className="leading-snug">{act}</span>
                            </div>
                          )) || (
                            <div className="text-xs italic text-zinc-500">Pantau antrean pengiriman email untuk mewaspadai potensi serangan phishing lanjutan.</div>
                          )}
                        </div>

                        {/* Export reports utility button */}
                        <button 
                          onClick={() => handleExportPhishingPDF(emailAnalysisResult)}
                          className="w-full mt-6 bg-red-800 hover:bg-red-750 text-white py-3 rounded-xl text-xs font-bold tracking-wider transition-all border border-red-900/50 flex items-center justify-center gap-2 cursor-pointer shadow-md shadow-red-950/20"
                        >
                          <Download size={14} />
                          EXPORT FORENSIC REPORT (PDF)
                        </button>
                      </div>
                    </div>

                  </div>
                </div>
              )}

            </div>
          )}
          {/* TAB 4: GENERAL AUDIT LOGS */}
          {activeTab === "logs" && (() => {
            const totalLogs = records.length;
            const highCriticalLogs = records.filter(r => r.severity === 'Critical' || r.severity === 'High').length;
            const threatPulsesLogs = records.reduce((acc, curr) => acc + (curr.threatIntel?.otxPulseCount || 0), 0);
            const clearSignatureRate = totalLogs > 0 ? Math.round((records.filter(r => r.severity === 'Low' || r.severity === 'Informational').length / totalLogs) * 100) : 100;

            const severityCountsLogs = {
              Critical: records.filter(r => r.severity === 'Critical').length,
              High: records.filter(r => r.severity === 'High').length,
              Medium: records.filter(r => r.severity === 'Medium').length,
              Low: records.filter(r => r.severity === 'Low').length,
              Informational: records.filter(r => r.severity === 'Informational').length,
            };

            const donutDataLogs = [
              { label: 'Critical', count: severityCountsLogs.Critical, color: '#ef4444' },
              { label: 'High', count: severityCountsLogs.High, color: '#f97316' },
              { label: 'Medium', count: severityCountsLogs.Medium, color: '#eab308' },
              { label: 'Low', count: severityCountsLogs.Low, color: '#3b82f6' },
              { label: 'Informational', count: severityCountsLogs.Informational, color: '#64748b' }
            ];

            const totalHitsForChartLogs = totalLogs || 1;
            let strokeAccumulatorLogs = 0;

            return (
              <div id="logs_history_section" className="space-y-6 animate-in fade-in duration-200">
                
                {/* Top Row: Balanced horizontal Stats Panel and Severity Proportions */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-4" id="reports_stats_and_proportions_grid">
                  
                  {/* Left Column: 4 ultra-compact stats cards */}
                  <div className="lg:col-span-7 grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {/* Card 1: Total Scanned */}
                    <div className="bg-[#0e0e12] border border-zinc-800 rounded-xl p-3 flex items-center justify-between shadow-md">
                      <div className="space-y-0.5 min-w-0">
                        <span className="text-[9px] text-zinc-400 font-mono tracking-wider uppercase block font-semibold truncate">Total Scanned</span>
                        <span className="text-xl font-bold font-display text-slate-100 block">{totalLogs}</span>
                      </div>
                      <div className="p-1.5 bg-zinc-900/60 text-indigo-400 rounded-lg border border-zinc-805 shrink-0 ml-1.5">
                        <Cpu size={14} />
                      </div>
                    </div>

                    {/* Card 2: Malicious Alerts */}
                    <div className="bg-[#0e0e12] border border-zinc-800 rounded-xl p-3 flex items-center justify-between shadow-md">
                      <div className="space-y-0.5 min-w-0">
                        <span className="text-[9px] text-zinc-400 font-mono tracking-wider uppercase block font-semibold truncate">Malicious Alerts</span>
                        <span className="text-xl font-bold font-display text-rose-400 block">{highCriticalLogs}</span>
                      </div>
                      <div className="p-1.5 bg-red-950/20 text-rose-400 rounded-lg border border-red-950/40 shrink-0 ml-1.5">
                        <AlertTriangle size={14} />
                      </div>
                    </div>

                    {/* Card 3: Threat Pulses Logged */}
                    <div className="bg-[#0e0e12] border border-zinc-800 rounded-xl p-3 flex items-center justify-between shadow-md">
                      <div className="space-y-0.5 min-w-0">
                        <span className="text-[9px] text-zinc-400 font-mono tracking-wider uppercase block font-semibold truncate">Threat Pulses</span>
                        <span className="text-xl font-bold font-display text-amber-400 block">{threatPulsesLogs}</span>
                      </div>
                      <div className="p-1.5 bg-amber-950/20 text-amber-400 rounded-lg border border-amber-950/40 shrink-0 ml-1.5">
                        <Network size={14} />
                      </div>
                    </div>

                    {/* Card 4: Clear Signature Rate */}
                    <div className="bg-[#0e0e12] border border-zinc-800 rounded-xl p-3 flex items-center justify-between shadow-md">
                      <div className="space-y-0.5 min-w-0">
                        <span className="text-[9px] text-zinc-400 font-mono tracking-wider uppercase block font-semibold truncate">Clear Rate</span>
                        <span className="text-xl font-bold font-display text-emerald-400 block">{clearSignatureRate}%</span>
                      </div>
                      <div className="p-1.5 bg-emerald-950/25 text-emerald-400 rounded-lg border border-emerald-950/40 shrink-0 ml-1.5">
                        <Shield size={14} />
                      </div>
                    </div>
                  </div>

                  {/* Right Column: Prominent Severity Proportions (giving it plenty of room to shine clearly) */}
                  <div className="lg:col-span-5 bg-[#0e0e12] border border-zinc-800 rounded-xl p-4 flex items-center gap-4 shadow-md min-w-0">
                    <div className="flex-1 min-w-0">
                      <span className="text-[10px] text-zinc-400 font-mono tracking-wider uppercase block font-bold mb-1">Severity Proportions</span>
                      <div className="flex gap-1 h-2 rounded-full overflow-hidden bg-zinc-900 border border-zinc-800 p-0.5 mb-2">
                        {totalLogs === 0 ? (
                          <div className="h-full w-full bg-zinc-850 rounded-full" />
                        ) : (
                          donutDataLogs.map((slice) => {
                            const pct = (slice.count / totalLogs) * 100;
                            if (pct === 0) return null;
                            return (
                              <div
                                key={slice.label}
                                style={{ width: `${pct}%`, backgroundColor: slice.color }}
                                className="h-full rounded-sm"
                                title={`${slice.label}: ${slice.count}`}
                              />
                            );
                          })
                        )}
                      </div>
                      <div className="grid grid-cols-2 gap-y-1 gap-x-2 text-[9px] font-mono text-zinc-500">
                        {donutDataLogs.map(slice => {
                          if (slice.count === 0 && totalLogs > 0) return null;
                          return (
                            <div key={slice.label} className="flex items-center gap-1 min-w-0">
                              <span className="w-1 h-1 rounded-full shrink-0" style={{ backgroundColor: slice.color }} />
                              <span className="text-zinc-300 font-medium truncate">{slice.label}</span>
                              <span className="text-zinc-400 ml-auto font-semibold">
                                {Math.round(totalLogs > 0 ? (slice.count / totalLogs) * 100 : 0)}%
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    <div className="flex shrink-0 items-center justify-center p-1.5 bg-zinc-950/60 border border-zinc-850/80 rounded-xl">
                      <svg width="44" height="44" viewBox="0 0 50 50" className="transform -rotate-90">
                        <circle cx="25" cy="25" r="18" fill="transparent" stroke="#1c1c24" strokeWidth="6" />
                        {(() => {
                          let miniStrokeAccum = 0;
                          return donutDataLogs.map((slice) => {
                            const percentage = (slice.count / totalHitsForChartLogs) * 100;
                            if (percentage === 0) return null;
                            const circum = 2 * Math.PI * 18;
                            const strokeDasharray = `${(percentage * circum) / 100} ${circum}`;
                            const strokeDashoffset = -miniStrokeAccum;
                            miniStrokeAccum += (percentage * circum) / 100;

                            return (
                              <circle
                                key={slice.label}
                                cx="25"
                                cy="25"
                                r="18"
                                fill="transparent"
                                stroke={slice.color}
                                strokeWidth="6"
                                strokeDasharray={strokeDasharray}
                                strokeDashoffset={strokeDashoffset}
                              />
                            );
                          });
                        })()}
                      </svg>
                    </div>
                  </div>

                </div>

                {/* Historical Audits and Database Index SECTION CONTAINER */}
                <div className="space-y-6" id="reports_historical_audits_container">
                  {/* Unified Header Row */}
                  <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-zinc-900/40 border border-zinc-800 rounded-xl p-6">
                    <div>
                      <h2 className="text-xl font-bold text-slate-100 font-display tracking-tight">Historical Audits and Database Index</h2>
                      <p className="text-sm text-zinc-400 mt-1">Laporan investigasi ancaman, reputasi deteksi IP/Domain/File Hash, dan audit intelijen historis.</p>
                    </div>
                    
                    <div className="flex flex-wrap items-center gap-2">
                      {/* Delete Selected */}
                      <button
                        onClick={handleDeleteSelected}
                        disabled={selectedLogIds.length === 0}
                        className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold font-mono border uppercase tracking-wider transition ${
                          selectedLogIds.length > 0
                            ? "bg-red-950/20 hover:bg-red-950/60 text-rose-400 border-red-900/35 cursor-pointer"
                            : "bg-zinc-900/40 text-zinc-500 border-zinc-850 cursor-not-allowed"
                        }`}
                      >
                        <Trash2 size={13} />
                        Delete Selected ({selectedLogIds.length})
                      </button>

                      {/* Export CSV */}
                      <button
                        onClick={handleExportCSV}
                        disabled={records.length === 0}
                        className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold font-mono border uppercase tracking-wider transition ${
                          records.length > 0
                            ? "bg-blue-950/20 hover:bg-blue-950/60 text-blue-400 border-blue-900/35 cursor-pointer"
                            : "bg-zinc-900/40 text-zinc-500 border-zinc-850 cursor-not-allowed"
                        }`}
                      >
                        <Download size={13} />
                        Export .csv
                      </button>
                    </div>
                  </div>

                  {/* Threat Index Database TABLE (Full 100% width) */}
                  <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6" id="reports_database_section">
                    <div className="flex justify-between items-center mb-4 pb-2 border-b border-zinc-805">
                      <h3 className="text-sm font-bold text-slate-200 tracking-wider uppercase font-mono">Threat Index Database</h3>
                      <span className="text-xs text-zinc-400 font-mono">Viewing {records.length} records</span>
                    </div>

                    {/* Comprehensive tables list */}
                    <div className="border border-zinc-800 rounded-xl overflow-x-auto font-mono text-[11px]">
                      <table className="w-full text-left border-collapse min-w-[700px]">
                        <thead className="bg-[#111115]/80 text-zinc-500 border-b border-zinc-800">
                          <tr>
                            <th className="p-3 w-10 text-center">
                              <input 
                                type="checkbox"
                                checked={records.length > 0 && selectedLogIds.length === records.length}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    setSelectedLogIds(records.map(r => r.id));
                                  } else {
                                    setSelectedLogIds([]);
                                  }
                                }}
                                className="rounded border-zinc-700 bg-zinc-950 text-blue-600 focus:ring-blue-500/20 cursor-pointer"
                              />
                            </th>
                            <th className="p-3">Indicator Target</th>
                            <th className="p-3">Type</th>
                            <th className="p-3">Risk Score</th>
                            <th className="p-3">Severity</th>
                            <th className="p-3">Timestamp</th>
                            <th className="p-3 text-right">Detail</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-800">
                          {records.length === 0 ? (
                            <tr>
                              <td colSpan={7} className="text-center p-12 text-zinc-500 italic">
                                Belum ada riwayat aktivitas penelusuran (audit logs) yang tercatat. Silakan lakukan pencarian indikator ancaman baru pada menu IOC Lookup atau Phishing Analyzer.
                              </td>
                            </tr>
                          ) : (
                            records.map((rec) => {
                              const isHigh = rec.severity === 'Critical' || rec.severity === 'High';
                              const isMed = rec.severity === 'Medium';
                              
                              return (
                                <tr key={rec.id} className="hover:bg-zinc-950/30 font-mono">
                                  <td className="p-3.5 text-center">
                                    <input 
                                      type="checkbox"
                                      checked={selectedLogIds.includes(rec.id)}
                                      onChange={(e) => {
                                        if (e.target.checked) {
                                          setSelectedLogIds(prev => [...prev, rec.id]);
                                        } else {
                                          setSelectedLogIds(prev => prev.filter(id => id !== rec.id));
                                        }
                                      }}
                                      className="rounded border-zinc-700 bg-zinc-950 text-blue-600 focus:ring-blue-500/20 cursor-pointer"
                                    />
                                  </td>
                                  <td className="p-3.5 font-semibold text-slate-200 select-all max-w-[130px] truncate" title={rec.ioc}>
                                    {rec.ioc}
                                  </td>
                                  <td className="p-3.5">
                                    <span className="bg-zinc-950 border border-zinc-800 px-2 py-0.5 rounded text-[9px] font-bold text-zinc-400 uppercase">
                                      {rec.type}
                                    </span>
                                  </td>
                                  <td className="p-3.5 text-slate-100 font-bold">{rec.riskScore}</td>
                                  <td className="p-3.5">
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                      isHigh 
                                        ? 'bg-rose-500/10 text-rose-400 border-rose-950/50' 
                                        : (isMed ? 'bg-amber-500/10 text-amber-400 border border-amber-950/50' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-950/50')
                                    }`}>
                                      {rec.severity}
                                    </span>
                                  </td>
                                  <td className="p-3.5 text-zinc-400 text-[10px]">
                                    {new Date(rec.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                                  </td>
                                  <td className="p-3.5 text-right font-sans flex items-center justify-end gap-2.5">
                                    <button
                                      onClick={() => handleSelectRecord(rec)}
                                      className="text-[10px] text-blue-400 hover:underline font-bold cursor-pointer"
                                    >
                                      Detail
                                    </button>
                                    <button
                                      onClick={() => handleDeleteSingleLog(rec.id)}
                                      className="p-1 rounded-md hover:bg-red-950/25 text-rose-400 border border-transparent hover:border-red-900/30 transition cursor-pointer"
                                      title="Delete Report"
                                    >
                                      <Trash2 size={12} />
                                    </button>
                                  </td>
                                </tr>
                              );
                            })
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>

              </div>
            );
          })()}

          {/* TAB 5: USER MANAGEMENT */}
          {activeTab === "users" && currentUser?.role === "Admin" && (
            <UserManagementView token={token} currentUser={currentUser} />
          )}

          {/* TAB 6: API INTEGRATIONS */}
          {activeTab === "integrations" && currentUser?.role === "Admin" && (
            <IntegrationSettingsView token={token} />
          )}

          {/* TAB 7: AUDIT LOGS */}
          {activeTab === "auditLogs" && currentUser?.role === "Admin" && (
            <AuditLogsView token={token} />
          )}

        </main>
      </div>
    </div>
  );
}
