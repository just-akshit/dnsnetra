"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

interface RiskGaugeProps {
  score: number;
  level: string;
}

const RiskGauge = ({ score, level }: RiskGaugeProps) => {
  const data = [
    { name: 'Risk', value: score },
    { name: 'Safe', value: 100 - score }
  ];

  const COLORS = ['#F97316', '#1E293B'];

  return (
    <div className="relative w-48 h-48 flex items-center justify-center">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            startAngle={220}
            endAngle={-40}
            innerRadius={70}
            outerRadius={90}
            paddingAngle={0}
            dataKey="value"
            stroke="none"
          >
            {data.map((_, index) => (
              <Cell 
                key={`cell-${index}`} 
                fill={COLORS[index % COLORS.length]} 
                style={index === 0 ? { filter: 'drop-shadow(0px 0px 8px rgba(249, 115, 22, 0.6))' } : {}}
              />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      
      {/* Outer decorative ring */}
      <div className="absolute inset-2 border border-slate-700 rounded-full opacity-30 pointer-events-none"></div>
      
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-5xl font-mono font-bold text-white text-glow">{score}</span>
        <span className="text-sm font-mono font-bold text-brand-orange tracking-widest mt-1 bg-brand-orange/10 px-2 rounded">{level}</span>
      </div>
    </div>
  );
};

export default RiskGauge;
