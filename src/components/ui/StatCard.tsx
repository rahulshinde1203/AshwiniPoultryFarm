interface StatCardProps {
  label: string;
  value: string;
  icon?: string;
  valueColor?: string;
  className?: string;
}

export function StatCard({
  label,
  value,
  icon,
  valueColor = 'text-gray-900 dark:text-slate-100',
  className = '',
}: StatCardProps) {
  return (
    <div
      className={`
        bg-white dark:bg-[#0F172A]
        rounded-2xl border border-gray-100 dark:border-slate-700/50
        shadow-sm p-4
        hover:shadow-md hover:scale-[1.02]
        transition-all duration-200
        ${className}
      `}
    >
      <div className="flex items-start justify-between mb-2">
        <p className="text-xs font-semibold text-gray-400 dark:text-slate-500 uppercase tracking-wide">
          {label}
        </p>
        {icon && <span className="text-xl">{icon}</span>}
      </div>
      <p className={`text-xl font-extrabold truncate ${valueColor}`}>{value}</p>
    </div>
  );
}
