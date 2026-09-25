"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { useAuth } from "../context/AuthContext";

const AuthPage = () => {
  const { user, login, register } = useAuth();
  const router = useRouter();
  const [isLogin, setIsLogin] = useState(true);
  
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (user) {
      router.replace("/overview");
    }
  }, [user, router]);

  if (user) {
    return null;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);
    try {
      if (isLogin) {
        await login(username, password);
      } else {
        await register(username, password);
      }
    } catch (err: any) {
      setError(
        isLogin 
          ? "Invalid username or password" 
          : (err.response?.data?.detail || "Registration failed. Try a different username.")
      );
    } finally {
      setIsLoading(false);
    }
  };

  const toggleView = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsLogin(!isLogin);
    setError("");
    setUsername("");
    setPassword("");
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center overflow-hidden bg-background font-sans text-foreground">
      {/* Background decorations for SOC aesthetic */}
      <div className="absolute inset-0 z-0 opacity-20 pointer-events-none" style={{
        backgroundImage: 'radial-gradient(circle at center, #334155 1px, transparent 1px)',
        backgroundSize: '24px 24px'
      }}></div>
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-brand-blue/10 blur-[120px] rounded-full pointer-events-none"></div>
      
      <div className="relative z-10 w-full max-w-md p-8 glass-card flex flex-col items-center overflow-hidden border border-border/50 shadow-[0_0_40px_rgba(0,0,0,0.5)]">
        
        {/* Header / Logo */}
        <div className="flex flex-col items-center mb-10">
          <div className="w-16 h-16 rounded-2xl bg-brand-blue/10 flex items-center justify-center border border-brand-blue/20 mb-4 shadow-[0_0_15px_rgba(59,130,246,0.2)]">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-brand-blue">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>
              <path d="m9 12 2 2 4-4"/>
            </svg>
          </div>
          <h1 className="text-2xl font-mono font-bold tracking-tight text-foreground text-glow">DNS THREAT</h1>
          <p className="text-xs font-mono text-slate-500 uppercase tracking-widest mt-1">Platform Access</p>
        </div>

        <div className="w-full relative min-h-[320px]">
          {/* LOGIN VIEW */}
          <div className={`absolute top-0 left-0 w-full transition-all duration-500 ease-in-out ${isLogin ? 'translate-x-0 opacity-100 pointer-events-auto' : '-translate-x-[120%] opacity-0 pointer-events-none'}`}>
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && isLogin && (
                <div className="text-destructive text-xs font-mono bg-destructive/10 border border-destructive/20 p-3 rounded-lg text-center flex items-center justify-center gap-2">
                  <span className="w-4 h-4 inline-flex items-center justify-center rounded-full bg-destructive/20">!</span>
                  {error}
                </div>
              )}
              
              <div>
                <label className="block text-slate-400 text-xs font-mono uppercase tracking-wider mb-2">Operator ID</label>
                <input 
                  type="text" 
                  required 
                  value={username} 
                  onChange={(e) => setUsername(e.target.value)} 
                  placeholder="admin@soc.local" 
                  className="w-full px-4 py-3 bg-secondary/50 text-foreground placeholder-slate-600 border border-border rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-blue focus:border-brand-blue transition-all font-mono text-sm" 
                />
              </div>
              
              <div>
                <div className="flex justify-between items-end mb-2">
                  <label className="block text-slate-400 text-xs font-mono uppercase tracking-wider">Passcode</label>
                  <a href="#" className="text-brand-blue/70 text-[10px] font-mono hover:text-brand-blue transition-colors uppercase tracking-wider">Reset</a>
                </div>
                <input 
                  type="password" 
                  required 
                  value={password} 
                  onChange={(e) => setPassword(e.target.value)} 
                  placeholder="••••••••" 
                  className="w-full px-4 py-3 bg-secondary/50 text-foreground placeholder-slate-600 border border-border rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-blue focus:border-brand-blue transition-all font-mono text-sm" 
                />
              </div>

              <button 
                type="submit" 
                disabled={isLoading} 
                className="w-full py-3 bg-brand-blue hover:bg-brand-blue/90 text-white font-mono font-bold text-sm tracking-wider uppercase rounded-lg flex justify-center items-center transition-colors disabled:opacity-50 disabled:cursor-not-allowed mt-6 shadow-[0_0_15px_rgba(59,130,246,0.3)]"
              >
                {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Authenticate"}
              </button>
            </form>
            
            <div className="mt-8 text-center border-t border-border/50 pt-6">
              <p className="text-slate-500 text-xs font-mono">
                Unauthorized access prohibited. <br className="mb-2"/>
                <button onClick={toggleView} className="text-brand-blue font-medium hover:text-brand-blue/80 hover:underline bg-transparent border-none cursor-pointer uppercase tracking-wider mt-2">Request Access</button>
              </p>
            </div>
          </div>

          {/* SIGNUP VIEW */}
          <div className={`absolute top-0 left-0 w-full transition-all duration-500 ease-in-out ${!isLogin ? 'translate-x-0 opacity-100 pointer-events-auto' : 'translate-x-[120%] opacity-0 pointer-events-none'}`}>
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && !isLogin && (
                <div className="text-destructive text-xs font-mono bg-destructive/10 border border-destructive/20 p-3 rounded-lg text-center flex items-center justify-center gap-2">
                  <span className="w-4 h-4 inline-flex items-center justify-center rounded-full bg-destructive/20">!</span>
                  {error}
                </div>
              )}
              
              <div>
                <label className="block text-slate-400 text-xs font-mono uppercase tracking-wider mb-2">Operator ID</label>
                <input 
                  type="text" 
                  required 
                  value={username} 
                  onChange={(e) => setUsername(e.target.value)} 
                  placeholder="admin@soc.local" 
                  className="w-full px-4 py-3 bg-secondary/50 text-foreground placeholder-slate-600 border border-border rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-blue focus:border-brand-blue transition-all font-mono text-sm" 
                />
              </div>
              
              <div>
                <label className="block text-slate-400 text-xs font-mono uppercase tracking-wider mb-2">Passcode</label>
                <input 
                  type="password" 
                  required 
                  value={password} 
                  onChange={(e) => setPassword(e.target.value)} 
                  placeholder="••••••••" 
                  className="w-full px-4 py-3 bg-secondary/50 text-foreground placeholder-slate-600 border border-border rounded-lg focus:outline-none focus:ring-1 focus:ring-brand-blue focus:border-brand-blue transition-all font-mono text-sm" 
                />
              </div>

              <button 
                type="submit" 
                disabled={isLoading} 
                className="w-full py-3 bg-brand-blue hover:bg-brand-blue/90 text-white font-mono font-bold text-sm tracking-wider uppercase rounded-lg flex justify-center items-center transition-colors disabled:opacity-50 disabled:cursor-not-allowed mt-6 shadow-[0_0_15px_rgba(59,130,246,0.3)]"
              >
                {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Request Provisioning"}
              </button>
            </form>
            
            <div className="mt-8 text-center border-t border-border/50 pt-6">
              <p className="text-slate-500 text-xs font-mono">
                Already provisioned? <br className="mb-2" />
                <button onClick={toggleView} className="text-brand-blue font-medium hover:text-brand-blue/80 hover:underline bg-transparent border-none cursor-pointer uppercase tracking-wider mt-2">Return to Login</button>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
export default AuthPage;
