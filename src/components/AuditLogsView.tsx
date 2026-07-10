import React, { useState, useEffect } from "react";
import { ClipboardList, Search, RefreshCw, AlertTriangle, ShieldCheck, MapPin, Tag, Trash2, Download } from "lucide-react";

interface AuditLogsViewProps {
  token: string | null;
}

export default function AuditLogsView({ token }: AuditLogsViewProps) {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [showConfirmDelete, setShowConfirmDelete] = useState(false);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/audit-logs", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (!res.ok) {
        throw new Error("Gagal mengambil data log audit siber.");
      }
      const data = await res.json();
      setLogs(data);
    } catch (err: any) {
      setError(err.message || "Gagal menghubungi modul log audit.");
    } finally {
      setLoading(false);
    }
  };

  // Search filter
  const filteredLogs = logs.filter((log) => {
    const query = searchQuery.toLowerCase().trim();
    if (!query) return true;
    return (
      (log.username || "").toLowerCase().includes(query) ||
      (log.action || "").toLowerCase().includes(query) ||
      (log.details || "").toLowerCase().includes(query) ||
      (log.role || "").toLowerCase().includes(query) ||
      (log.ipAddress || "").toLowerCase().includes(query)
    );
  });

  const isAllSelected = filteredLogs.length > 0 && filteredLogs.every(log => selectedIds.includes(log.id));

  const handleSelectAll = () => {
    if (isAllSelected) {
      const filteredIds = filteredLogs.map(log => log.id);
      setSelectedIds(prev => prev.filter(id => !filteredIds.includes(id)));
    } else {
      const filteredIds = filteredLogs.map(log => log.id);
      setSelectedIds(prev => {
        const newSet = new Set([...prev, ...filteredIds]);
        return Array.from(newSet);
      });
    }
  };

  const handleSelectRow = (id: string) => {
    setSelectedIds(prev =>
      prev.includes(id) ? prev.filter(item => item !== id) : [...prev, id]
    );
  };

  const handleDeleteSelected = async () => {
    if (selectedIds.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/audit-logs", {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ ids: selectedIds })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Gagal menghapus log audit.");
      }

      const data = await res.json();
      setLogs(data.logs || []);
      setSelectedIds([]);
      setShowConfirmDelete(false);
    } catch (err: any) {
      setError(err.message || "Gagal menghapus log.");
    } finally {
      setLoading(false);
    }
  };

  const exportToCSV = () => {
    if (filteredLogs.length === 0) return;

    const headers = ["Timestamp", "Analyst User", "Role", "IP Address", "Action Event", "Details"];
    const csvRows = [
      headers.join(","),
      ...filteredLogs.map(log => {
        const timestamp = new Date(log.timestamp).toISOString();
        const username = `"${(log.username || "").replace(/"/g, '""')}"`;
        const role = `"${(log.role || "").replace(/"/g, '""')}"`;
        const ipAddress = `"${(log.ipAddress || "").replace(/"/g, '""')}"`;
        const action = `"${(log.action || "").replace(/"/g, '""')}"`;
        const details = `"${(log.details || "").replace(/"/g, '""')}"`;
        return [timestamp, username, role, ipAddress, action, details].join(",");
      })
    ];

    const csvContent = csvRows.join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `cyberlens_audit_logs_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6" id="audit_logs_section">
      
      {/* Description header */}
      <div className="flex flex-col md:flex-row md:justify-between md:items-center gap-4 bg-[#0d0d11]/40 border border-zinc-800 rounded-xl p-5">
        <div>
          <h2 className="text-xl font-bold text-slate-100 font-display">System Audit Logs</h2>
          <p className="text-xs text-zinc-400 mt-1">
            Log audit terenskripsi dan tercatat secara berurutan. Menyimpan bukti login, penambahan user, modifikasi konfigurasi integrasi API, lookup IOC, dan analisis email phishing.
          </p>
        </div>
      </div>

      {/* Select All, Actions, Export, and Refresh Controllers Panel */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-zinc-950/60 border border-zinc-850 rounded-xl p-4 text-xs font-mono">
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 cursor-pointer text-zinc-400 hover:text-zinc-200 select-none">
            <input 
              type="checkbox" 
              id="audit-log-select-all"
              checked={isAllSelected}
              onChange={handleSelectAll}
              className="rounded bg-zinc-900 border-zinc-800 text-blue-500 focus:ring-0 focus:ring-offset-0 cursor-pointer h-4 w-4"
            />
            <span className="font-semibold uppercase tracking-wider text-[11px]">Select All</span>
          </label>
          {selectedIds.length > 0 && (
            <span className="text-blue-400 text-[10px] font-bold bg-blue-950/40 px-2 py-0.5 rounded border border-blue-900/40">
              {selectedIds.length} Terpilih
            </span>
          )}
        </div>
        
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setShowConfirmDelete(true)}
            disabled={selectedIds.length === 0 || loading}
            id="btn-delete-audit-logs"
            className={`px-3.5 py-2.5 rounded-lg border text-[10px] font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed ${
              selectedIds.length > 0 
                ? "bg-rose-950/45 text-rose-450 border-rose-900/60 hover:bg-rose-900/20 shadow-lg shadow-rose-950/10" 
                : "bg-zinc-900/30 text-zinc-500 border-zinc-850"
            }`}
          >
            <Trash2 size={13} />
            Delete Selected
          </button>

          <button
            onClick={exportToCSV}
            disabled={filteredLogs.length === 0}
            id="btn-export-audit-csv"
            className="px-3.5 py-2.5 bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 rounded-lg text-zinc-300 hover:text-white transition-all text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <Download size={13} />
            Export CSV
          </button>

          <button
            onClick={fetchLogs}
            disabled={loading}
            id="btn-refresh-audit-logs"
            className="px-3.5 py-2.5 bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 rounded-lg text-zinc-350 hover:text-white transition-all text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 cursor-pointer"
          >
            <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {showConfirmDelete && (
        <div className="bg-rose-950/15 border border-rose-900/65 rounded-xl p-5 text-xs font-mono space-y-3 shadow-lg shadow-rose-950/20" id="delete_confirm_panel">
          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-rose-500/10 border border-rose-500/25 rounded-lg text-rose-450 mt-0.5">
              <AlertTriangle size={16} />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-100 uppercase tracking-wide">Konfirmasi Penghapusan Log</h4>
              <p className="text-zinc-400 text-[11px] mt-0.5 leading-normal">
                Anda akan menghapus secara permanen <span className="text-rose-400 font-bold">{selectedIds.length}</span> baris catatan log siber dari ledger. Tindakan ini tidak dapat dibatalkan.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 pt-1 pl-12">
            <button
              onClick={handleDeleteSelected}
              disabled={loading}
              id="confirm_delete_btn"
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg font-bold uppercase tracking-wider transition-colors cursor-pointer disabled:opacity-50"
            >
              {loading ? "Menghapus..." : "Ya, Hapus Permanen"}
            </button>
            <button
              onClick={() => setShowConfirmDelete(false)}
              disabled={loading}
              id="cancel_delete_btn"
              className="px-4 py-2 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-350 hover:text-white rounded-lg font-bold uppercase tracking-wider transition-colors cursor-pointer disabled:opacity-50"
            >
              Batal
            </button>
          </div>
        </div>
      )}

      {/* Filter and Search box */}
      <div className="bg-[#0d0d11]/40 border border-zinc-800 rounded-xl p-5 flex items-center relative">
        <span className="absolute pl-3.5 text-zinc-650">
          <Search size={18} />
        </span>
        <input
          type="text"
          id="input-search-audit-logs"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Cari logs berdasarkan username, aksi siber (cth: USER_LOGIN, INTEGRATION), alamat IP, atau rincian spesifik log..."
          className="w-full bg-zinc-950/80 border border-zinc-850 rounded-xl pl-11 pr-4 py-3 text-sm text-slate-100 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
        />
      </div>

      {error && (
        <div className="p-3 bg-rose-950/20 border border-rose-900/50 text-rose-400 rounded-xl text-xs flex items-center gap-2 font-mono">
          <AlertTriangle size={15} />
          <span>{error}</span>
        </div>
      )}

      {/* Logs Table */}
      <div className="bg-[#0d0d11]/40 border border-zinc-800 rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 font-mono flex items-center gap-2">
          <ClipboardList size={16} className="text-blue-500" />
          SOC Compliance ledger
        </h3>

        <div className="border border-zinc-800 overflow-hidden rounded-xl font-mono text-[11px]">
          <table className="w-full text-left">
            <thead className="bg-[#111115] text-zinc-500 border-b border-zinc-850">
              <tr>
                <th className="p-3.5 w-10 text-center">
                  <input 
                    type="checkbox" 
                    checked={isAllSelected}
                    onChange={handleSelectAll}
                    className="rounded bg-zinc-900 border-zinc-800 text-blue-500 focus:ring-0 focus:ring-offset-0 cursor-pointer h-3.5 w-3.5"
                  />
                </th>
                <th className="p-3.5">Timestamp (UTC)</th>
                <th className="p-3.5">Analyst User</th>
                <th className="p-3.5">Role</th>
                <th className="p-3.5">IP Address</th>
                <th className="p-3.5">Action Event</th>
                <th className="p-3.5">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-850">
              {loading ? (
                <tr>
                  <td colSpan={7} className="p-16 text-center text-zinc-500 italic">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="animate-spin text-zinc-500" size={14} />
                      Membuka ledger audit siber...
                    </div>
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-zinc-500 italic">
                    Belum menemukan catatan log yang sesuai dengan kata pencarian Anda.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => {
                  const isCritAction = log.action === "LOGIN_FAILED" || log.action === "USER_DELETED" || log.action === "PASSWORD_CHANGED" || log.action === "AUDIT_LOG_DELETED";
                  const isConfigAction = log.action.includes("INTEGRATION") || log.action === "USER_CREATED";
                  const isSelected = selectedIds.includes(log.id);
                  
                  return (
                    <tr key={log.id} className={`hover:bg-zinc-950/20 transition-colors ${isSelected ? "bg-blue-950/15" : ""}`}>
                      <td className="p-3 text-center">
                        <input 
                          type="checkbox" 
                          id={`audit_log_checkbox_${log.id}`}
                          checked={isSelected}
                          onChange={() => handleSelectRow(log.id)}
                          className="rounded bg-zinc-900 border-zinc-800 text-blue-500 focus:ring-0 focus:ring-offset-0 cursor-pointer h-3.5 w-3.5"
                        />
                      </td>
                      <td className="p-3 text-zinc-400 font-mono whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleDateString()} {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="p-3 font-semibold text-slate-100">{log.username}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${
                          log.role === "Admin" 
                            ? "bg-rose-500/10 text-rose-450 border-rose-950/60" 
                            : log.role === "Analyst" 
                              ? "bg-amber-500/10 text-amber-450 border-amber-950/60"
                              : "bg-emerald-500/10 text-emerald-450 border-emerald-950/60"
                        }`}>
                          {log.role}
                        </span>
                      </td>
                      <td className="p-3 text-zinc-400 font-semibold">{log.ipAddress}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isCritAction 
                            ? "bg-rose-500/15 text-rose-400 border border-rose-950" 
                            : isConfigAction
                              ? "bg-blue-500/15 text-blue-400 border border-blue-950" 
                              : "bg-zinc-800 text-zinc-350"
                        }`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="p-3 text-slate-200 select-all leading-normal max-w-sm font-semibold">{log.details}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
