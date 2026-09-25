"use client";

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Search, Bell, Clock, ChevronDown, User } from 'lucide-react';

const Header = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const router = useRouter();

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = searchTerm.trim();
    if (!clean) return;

    // Check if IPv4 / IPv6 address
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(':');
    if (isIp) {
      router.push(`/investigate/clients/${encodeURIComponent(clean)}`);
    } else {
      router.push(`/investigate/domains/${encodeURIComponent(clean)}`);
    }
    setSearchTerm('');
  };

  return (
    <header className="h-16 flex items-center justify-between px-6 bg-secondary/30 border-b border-border backdrop-blur-md">
      <div className="flex items-center space-x-4">
        <h2 className="text-xl font-mono font-bold text-foreground tracking-tight flex items-center space-x-2">
          <span>ENTERPRISE SECURITY</span>
        </h2>
      </div>
      
      <div className="flex items-center space-x-6">
        <form onSubmit={handleSearch} className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input 
            type="text" 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Investigate domain or IP..." 
            className="pl-9 pr-4 py-1.5 bg-background border border-border rounded-md text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary w-64 font-mono transition-all placeholder:text-slate-500"
          />
        </form>
        
        <div className="flex items-center space-x-2 bg-background border border-border rounded-md px-3 py-1.5 cursor-pointer hover:bg-muted transition-colors">
          <Clock className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-foreground font-mono">Last 24 Hours</span>
          <ChevronDown className="w-4 h-4 text-slate-400" />
        </div>
        
        <div className="flex items-center space-x-4 border-l border-border pl-6">
          <button className="text-slate-400 hover:text-foreground transition-colors">
            <Bell className="w-5 h-5" />
          </button>
          <button className="text-slate-400 hover:text-foreground transition-colors">
            <User className="w-5 h-5" />
          </button>
        </div>
      </div>
    </header>
  );
};

export default Header;
