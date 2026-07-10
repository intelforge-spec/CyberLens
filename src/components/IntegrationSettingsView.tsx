import React, { useState, useEffect } from "react";
import { Settings, CheckCircle, XCircle, AlertCircle, RefreshCw, Server, Shield, Globe, Terminal, Network, Search } from "lucide-react";

interface IntegrationSettingsViewProps {
  token: string | null;
}

export default function IntegrationSettingsView({ token }: IntegrationSettingsViewProps) {
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [newKey, setNewKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [testLoading, setTestLoading] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/integrations", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (!res.ok) {
        throw new Error("Gagal mengambil data konfigurasi integrasi.");
      }
      const data = await res.json();
      setIntegrations(data);
    } catch (err: any) {
      setError(err.message || "Gagal memanggil modul API integrasi.");
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateKey = async (id: string, name: string) => {
    if (!newKey.trim()) {
      setError("Isi kunci API / API Key rahasia terlebih dahulu.");
      return;
    }

    setActionLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const res = await fetch(`/api/integrations/${id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ apiKey: newKey.trim() })
      });

      if (!res.ok) {
        throw new Error("Gagal memperbarui API key integrasi.");
      }

      setSuccess(`Konfigurasi API Key untuk "${name}" berhasil dienkripsi dan disimpan.`);
      setEditingId(null);
      setNewKey("");
      fetchIntegrations();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleTestConnection = async (id: string, name: string) => {
    setTestLoading(id);
    setError(null);
    setSuccess(null);

    try {
      const res = await fetch(`/api/integrations/${id}/test`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });

      if (!res.ok) {
        throw new Error("Tindakan uji koneksi gagal mengeksusi command.");
      }

      const result = await res.json();
      setSuccess(`Hasil Uji "${name}": Server merespons dengan status "${result.status}".`);
      fetchIntegrations();
    } catch (err: any) {
      setError(err.message || `Gagal menghubungi konektivitas endpoint "${name}".`);
    } finally {
      setTestLoading(null);
    }
  };

  return (
    <div className="space-y-6" id="integrations_section">
      <div className="flex justify-between items-center bg-[#0d0d11]/40 border border-zinc-800 rounded-xl p-5">
        <div>
          <h2 className="text-xl font-bold text-slate-100 font-display">Integration Settings</h2>
          <p className="text-xs text-zinc-400 mt-1">
            Konfigurasikan API key untuk database reputasi global ancaman siber. Kunci didekripsi hanya di memori server saat melakukan query investigasi real-time.
          </p>
        </div>
        <button
          onClick={fetchIntegrations}
          className="p-2.5 bg-zinc-900 hover:bg-zinc-850 rounded-xl text-zinc-400 hover:text-zinc-200 border border-zinc-800 transition"
          title="Refresh Feed"
        >
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
        </button>
      </div>

      {error && (
        <div className="p-3 bg-rose-950/20 border border-rose-900/50 text-rose-400 rounded-xl text-xs flex items-center gap-2 font-mono">
          <AlertCircle size={15} />
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="p-3 bg-emerald-950/15 border border-emerald-900/40 text-emerald-405 text-emerald-400 rounded-xl text-xs flex items-center gap-2 font-mono">
          <CheckCircle size={15} />
          <span>{success}</span>
        </div>
      )}

      {loading ? (
        <div className="p-16 border border-zinc-800 rounded-xl bg-zinc-900/10 flex flex-col items-center justify-center gap-3">
          <RefreshCw className="animate-spin text-blue-500" size={24} />
          <span className="text-xs font-mono text-zinc-500 italic">Mengecek parameter kriptografi integrasi ancaman siber...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6" id="integrations_grid">
          {integrations.map((item) => {
            const isEditing = editingId === item.id;
            
            const isConnected = item.status === "Connected";
            const isDisconnected = item.status === "Disconnected";
            const isRateLimited = item.status === "Rate Limited";
            const isInvalidKey = item.status === "Invalid API Key";

            let iconOfProvider = <Server size={18} />;
            if (item.id === "virustotal") iconOfProvider = <Globe size={18} />;
            if (item.id === "abuseipdb") iconOfProvider = <Terminal size={18} />;
            if (item.id === "alienvault") iconOfProvider = <Network size={18} />;
            if (item.id === "malwarebazaar") iconOfProvider = <Shield size={18} />;
            if (item.id === "urlhaus") iconOfProvider = <Search size={18} />;

            return (
              <div key={item.id} className="bg-[#0d0d11]/45 border border-zinc-800 rounded-xl p-6 space-y-4 shadow-sm flex flex-col justify-between">
                <div>
                  
                  {/* Title card header */}
                  <div className="flex justify-between items-start gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 bg-zinc-900 border border-zinc-800 rounded-lg text-blue-400">
                        {iconOfProvider}
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-slate-100 font-display">{item.name}</h3>
                        <span className="text-[10px] text-zinc-500 font-mono block tracking-wider uppercase font-semibold">
                          Provider: {item.provider}
                        </span>
                      </div>
                    </div>

                    {/* Status Badge */}
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase border flex items-center gap-1.5 ${
                      isConnected 
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-950/60' 
                        : isDisconnected
                          ? 'bg-zinc-800/10 text-zinc-400 border-zinc-850'
                          : isRateLimited
                            ? 'bg-amber-500/10 text-amber-400 border-amber-950/60'
                            : 'bg-rose-500/10 text-rose-400 border-rose-950/60'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${isConnected ? "bg-emerald-500 animate-pulse" : (isDisconnected ? "bg-zinc-500" : (isRateLimited ? "bg-amber-500" : "bg-rose-500"))}`}></span>
                      {item.status}
                    </span>
                  </div>

                  <p className="text-xs text-zinc-400 leading-relaxed mt-3 font-medium">
                    {item.description || "Integrasikan feed ancaman untuk mendeteksi indikator ini secara otomatis pada dasbor utama."}
                  </p>
                </div>

                {/* API Key value mapping / editing section */}
                <div className="space-y-3 pt-3 border-t border-zinc-850/60 font-mono text-xs">
                  {isEditing ? (
                    <div className="space-y-2">
                      <label className="text-[10px] uppercase font-bold text-zinc-500 block">Masukkan API Key Rahasia:</label>
                      <div className="flex gap-2">
                        <input
                          type="password"
                          value={newKey}
                          onChange={(e) => setNewKey(e.target.value)}
                          placeholder="Masukkan nilai aktual key..."
                          className="flex-1 bg-zinc-950/90 border border-blue-500/40 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder:text-zinc-650 focus:outline-none"
                        />
                        <button
                          onClick={() => handleUpdateKey(item.id, item.name)}
                          disabled={actionLoading}
                          className="bg-blue-600 hover:bg-blue-500 px-3 py-1.5 rounded-lg text-white font-bold tracking-tight text-[11px] cursor-pointer"
                        >
                          Simpan
                        </button>
                        <button
                          onClick={() => { setEditingId(null); setNewKey(""); }}
                          className="bg-zinc-900 border border-zinc-800 hover:bg-zinc-855 px-2.5 py-1.5 rounded-lg text-zinc-300 font-semibold"
                        >
                          Batal
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex justify-between items-center bg-zinc-950/40 p-2.5 rounded-lg border border-zinc-850">
                      <div>
                        <span className="text-[10px] text-zinc-500 uppercase block leading-none font-bold mb-1">Stored API Key Token:</span>
                        <span className="text-[11px] text-zinc-350 select-all block truncate max-w-[210px]" title={item.apiKeyMasked}>
                          {item.apiKeyMasked || "Tidak dikonfigurasi"}
                        </span>
                      </div>
                      <button
                        onClick={() => { setEditingId(item.id); setNewKey(""); }}
                        className="text-[11px] text-blue-400 hover:underline font-bold"
                      >
                        Edit Key
                      </button>
                    </div>
                  )}

                  {/* Actions buttons */}
                  <div className="flex justify-between items-center text-[11px] text-zinc-500">
                    <span>Tested: {item.lastTestedTime ? new Date(item.lastTestedTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + " UTC" : "Belum pernah diuji"}</span>
                    
                    <button
                      onClick={() => handleTestConnection(item.id, item.name)}
                      disabled={testLoading !== null}
                      className="px-3 py-1.5 bg-zinc-900 hover:bg-zinc-850 text-zinc-300 hover:text-zinc-100 rounded-lg border border-zinc-800 cursor-pointer flex items-center justify-center gap-1 leading-none font-semibold transition"
                    >
                      {testLoading === item.id ? (
                        <>
                          <RefreshCw className="animate-spin text-blue-500" size={12} />
                          Testing...
                        </>
                      ) : (
                        <>
                          Uji Koneksi
                        </>
                      )}
                    </button>
                  </div>
                </div>

              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
