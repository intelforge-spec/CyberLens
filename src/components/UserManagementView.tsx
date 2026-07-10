import React, { useState, useEffect } from "react";
import { Users, UserPlus, Trash2, Shield, RefreshCw, AlertTriangle, CheckCircle, Clock } from "lucide-react";

interface UserManagementViewProps {
  token: string | null;
  currentUser: any;
}

export default function UserManagementView({ token, currentUser }: UserManagementViewProps) {
  const [users, setUsers] = useState<any[]>([]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"Admin" | "Analyst" | "Viewer">("Analyst");
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [userToDelete, setUserToDelete] = useState<{ id: string; username: string } | null>(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/users", {
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });
      if (!res.ok) {
        throw new Error("Gagal memuat daftar analis sistem.");
      }
      const data = await res.json();
      setUsers(data);
    } catch (err: any) {
      setError(err.message || "Gagal menghubungi database pengguna.");
    } finally {
      setLoading(false);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError("Username dan password wajib ditentukan.");
      return;
    }

    setActionLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const res = await fetch("/api/users", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ username: username.trim(), password, role })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Gagal membuat pengguna baru.");
      }

      setSuccess(`Akun analis baru "${username}" dengan peran "${role}" berhasil dibuat.`);
      setUsername("");
      setPassword("");
      setRole("Analyst");
      fetchUsers();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteUser = async (id: string, targetUsername: string) => {
    if (targetUsername === currentUser.username) {
      setError("Anda tidak diperkenankan menghapus akun Anda sendiri.");
      return;
    }
    setError(null);
    setSuccess(null);
    setUserToDelete({ id, username: targetUsername });
  };

  const executeDeleteUser = async () => {
    if (!userToDelete) return;
    const { id, username: targetUsername } = userToDelete;
    setUserToDelete(null);

    setActionLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const res = await fetch(`/api/users/${id}`, {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Gagal menghapus pengguna.");
      }

      setSuccess(`Akun analis "${targetUsername}" berhasil terminated.`);
      fetchUsers();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="space-y-6" id="user_management_section">
      <div className="flex justify-between items-center bg-[#0d0d11]/40 border border-zinc-800 rounded-xl p-5">
        <div>
          <h2 className="text-xl font-bold text-slate-100 font-display">User Management</h2>
          <p className="text-xs text-zinc-400 mt-1">
            Tambahkan analis cybersecurity baru, edit hak akses dengan model role-based access control (RBAC), atau nonaktifkan akun analis dari sistem.
          </p>
        </div>
        <button
          onClick={fetchUsers}
          className="p-2.5 bg-zinc-900 hover:bg-zinc-850 rounded-xl text-zinc-400 hover:text-zinc-200 border border-zinc-800 transition"
          title="Refresh List"
        >
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Registration Form */}
        <form onSubmit={handleCreateUser} className="lg:col-span-4 bg-[#0d0d11]/40 border border-zinc-800 rounded-xl p-6 h-fit space-y-4">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 font-mono flex items-center gap-2 pb-2 border-b border-zinc-800">
            <UserPlus size={16} className="text-blue-500" />
            Provision New Analyst
          </h3>

          <div className="space-y-1.5">
            <label className="text-xs font-mono uppercase text-zinc-500 font-bold">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Masukkan username analis"
              className="w-full bg-zinc-950/85 border border-zinc-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 placeholder:text-zinc-650 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-mono uppercase text-zinc-500 font-bold">Default Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Masukkan sandi otorisasi"
              className="w-full bg-zinc-950/85 border border-zinc-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 placeholder:text-zinc-650 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-mono uppercase text-zinc-500 font-bold">System Role Badge</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as any)}
              className="w-full bg-zinc-950/85 border border-zinc-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono cursor-pointer"
            >
              <option value="Admin">Admin (Full Access & Settings)</option>
              <option value="Analyst">Analyst (Lookup & Email Analyzer)</option>
              <option value="Viewer">Viewer (Dashboard & Reports Read-Only)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={actionLoading}
            className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold tracking-wider transition duration-150 cursor-pointer flex items-center justify-center gap-1.5"
          >
            <UserPlus size={14} />
            PROVISION ACCOUNT
          </button>
        </form>

        {/* Users Table */}
        <div className="lg:col-span-8 bg-[#0d0d11]/40 border border-zinc-800 rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 font-mono flex items-center gap-2">
            <Users size={16} className="text-blue-500" />
            Registered SOC Analysts Directory
          </h3>

          {error && (
            <div className="p-3 bg-rose-950/20 border border-rose-900/50 text-rose-400 rounded-lg text-xs flex items-center gap-2 font-mono">
              <AlertTriangle size={15} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="p-3 bg-emerald-950/20 border border-emerald-900/50 text-emerald-400 rounded-lg text-xs flex items-center gap-2 font-mono">
              <CheckCircle size={15} />
              <span>{success}</span>
            </div>
          )}

          <div className="border border-zinc-800 overflow-hidden rounded-xl font-mono text-xs">
            <table className="w-full text-left">
              <thead className="bg-[#111115] text-zinc-500 border-b border-zinc-850">
                <tr>
                  <th className="p-3">Analyst Accounts</th>
                  <th className="p-3">Verified Role</th>
                  <th className="p-3">Registered Time (UTC)</th>
                  <th className="p-3 text-right">Operation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-850">
                {loading ? (
                  <tr>
                    <td colSpan={4} className="p-10 text-center text-zinc-550 flex items-center justify-center gap-2 italic">
                      <RefreshCw className="animate-spin text-zinc-500" size={14} />
                      Menghubungi direktori internal CyberLens...
                    </td>
                  </tr>
                ) : users.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-zinc-500 italic">
                      Tidak ada analis lain terdaftar ke dalam platform.
                    </td>
                  </tr>
                ) : (
                  users.map((u) => {
                    const isAdmin = u.role === "Admin";
                    const isAnalyst = u.role === "Analyst";
                    const isCurrentUser = u.username === currentUser.username;

                    return (
                      <tr key={u.id} className="hover:bg-zinc-950/30">
                        <td className="p-3 font-semibold text-slate-100 flex items-center gap-2">
                          {u.username}
                          {isCurrentUser && (
                            <span className="text-[10px] bg-blue-500/10 text-blue-400 border border-blue-900/50 px-1.5 py-0.25 rounded">
                              Current Session
                            </span>
                          )}
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            isAdmin 
                              ? "bg-rose-500/10 text-rose-400 border-rose-950/80" 
                              : isAnalyst 
                                ? "bg-amber-500/10 text-amber-400 border-amber-950/80" 
                                : "bg-emerald-500/10 text-emerald-400 border-emerald-950/80"
                          }`}>
                            {u.role}
                          </span>
                        </td>
                        <td className="p-3 text-zinc-400">
                          {new Date(u.createdAt).toLocaleDateString()} {new Date(u.createdAt).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})}
                        </td>
                        <td className="p-3 text-right">
                          <button
                            onClick={() => handleDeleteUser(u.id, u.username)}
                            disabled={isCurrentUser}
                            className={`p-1.5 rounded-lg border text-rose-400 transition ${
                              isCurrentUser 
                                ? "opacity-30 cursor-not-allowed border-zinc-800" 
                                : "bg-red-950/10 hover:bg-red-950/40 border-red-900/35 cursor-pointer"
                            }`}
                            title={isCurrentUser ? "Anda tidak dapat menghapus diri sendiri" : "Terminasi Sesi Akun"}
                          >
                            <Trash2 size={13} />
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

      {/* Custom Confirmation Modal */}
      {userToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-sm bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-2xl space-y-4 animate-in fade-in duration-200">
            <div className="flex items-start gap-3">
              <div className="p-2.5 bg-rose-500/10 text-rose-400 rounded-xl border border-rose-950/50 shrink-0">
                <AlertTriangle size={20} />
              </div>
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-slate-100 font-mono uppercase tracking-wide">Konfirmasi Hapus Akun</h4>
                <p className="text-[11px] text-zinc-400 leading-relaxed">
                  Apakah Anda yakin ingin memblokir dan menghapus akun analis <span className="text-rose-400 font-bold font-mono">"{userToDelete.username}"</span>?
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setUserToDelete(null)}
                className="px-3.5 py-2 bg-zinc-900 hover:bg-zinc-850 text-zinc-400 hover:text-zinc-200 rounded-lg text-[11px] font-mono font-bold transition border border-zinc-800 cursor-pointer"
              >
                BATAL
              </button>
              <button
                type="button"
                onClick={executeDeleteUser}
                className="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-[11px] font-mono font-bold transition cursor-pointer flex items-center gap-1"
              >
                <Trash2 size={12} />
                TERMINASI
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
