import React, { useState } from "react";
import { ShieldAlert, KeyRound, AlertTriangle, RefreshCw } from "lucide-react";

interface LoginViewProps {
  onLoginSuccess: (token: string, user: any) => void;
}

export default function LoginView({ onLoginSuccess }: LoginViewProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError("Username dan password tidak boleh kosong.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Kombinasi kredensial salah.");
      }

      const data = await res.json();
      localStorage.setItem("cyberlens_token", data.token);
      localStorage.setItem("cyberlens_user", JSON.stringify(data.user));
      onLoginSuccess(data.token, data.user);
    } catch (err: any) {
      setError(err.message || "Gagal menghubungi server autentikasi.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070709] bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(30,58,138,0.2),rgba(255,255,255,0))] flex flex-col items-center justify-center p-6 text-zinc-100" id="login_container">
      <div className="w-full max-w-md bg-[#0d0d11]/85 border border-zinc-800/85 rounded-2xl shadow-2xl p-8 space-y-6 backdrop-blur-md">
        
        {/* Branding */}
        <div className="space-y-2 text-center">
          <div className="mx-auto w-14 h-14 bg-blue-600/10 border-2 border-blue-500 rounded-2xl flex items-center justify-center shadow-lg shadow-blue-950/20">
            <ShieldAlert className="text-blue-400" size={28} />
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-tight font-display text-white">CyberLens Portal</h1>
            <span className="text-[10px] text-zinc-500 font-mono tracking-widest block uppercase mt-1">SOC SECURITY SURVEILLANCE V2.1</span>
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-1.5 text-left">
            <label className="text-xs font-mono uppercase text-zinc-400 font-bold tracking-wider">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
              className="w-full bg-zinc-950/80 border border-zinc-800 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 font-mono"
              disabled={loading}
              id="login_username_field"
            />
          </div>

          <div className="space-y-1.5 text-left">
            <label className="text-xs font-mono uppercase text-zinc-400 font-bold tracking-wider">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              className="w-full bg-zinc-950/80 border border-zinc-800 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder:text-zinc-650 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 font-mono"
              disabled={loading}
              id="login_password_field"
            />
          </div>

          {error && (
            <div className="p-3 bg-rose-950/30 border border-rose-900/50 text-rose-400 rounded-xl text-xs flex items-center gap-2.5 font-mono">
              <AlertTriangle size={15} className="shrink-0 text-rose-500" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-semibold transition duration-200 shadow-lg shadow-blue-950/30 cursor-pointer disabled:opacity-40 flex items-center justify-center gap-2 font-mono"
            id="login_submit_btn"
          >
            {loading ? (
              <>
                <RefreshCw className="animate-spin text-white" size={16} />
                Mengevaluasi Kredensial...
              </>
            ) : (
              <>
                <KeyRound size={16} />
                Sign In to CyberLens
              </>
            )}
          </button>
        </form>

      </div>
    </div>
  );
}


