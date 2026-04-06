import { ReactNode } from 'react';

export function TableWrapper({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div className={`overflow-x-auto ${className}`}>
      <table className="w-full text-sm">{children}</table>
    </div>
  );
}

export function TableHead({ children }: { children: ReactNode }) {
  return (
    <thead className="bg-gray-50 dark:bg-slate-800/60 border-b border-gray-100 dark:border-slate-700 sticky top-0">
      {children}
    </thead>
  );
}

export function Th({ children, className = '' }: { children?: ReactNode; className?: string }) {
  return (
    <th
      className={`text-left text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wide px-4 py-3 whitespace-nowrap ${className}`}
    >
      {children}
    </th>
  );
}

export function TableBody({ children }: { children: ReactNode }) {
  return (
    <tbody className="divide-y divide-gray-50 dark:divide-slate-700/40">
      {children}
    </tbody>
  );
}

export function Tr({
  children,
  className = '',
  zebra = false,
  index = 0,
}: {
  children: ReactNode;
  className?: string;
  zebra?: boolean;
  index?: number;
}) {
  return (
    <tr
      className={`
        hover:bg-gray-50/80 dark:hover:bg-slate-800/50
        ${zebra && index % 2 === 1 ? 'bg-gray-50/40 dark:bg-slate-800/20' : ''}
        transition-colors ${className}
      `}
    >
      {children}
    </tr>
  );
}

export function Td({ children, className = '' }: { children?: ReactNode; className?: string }) {
  return (
    <td className={`px-4 py-3.5 ${className}`}>{children}</td>
  );
}
