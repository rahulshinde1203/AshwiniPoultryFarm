import { ReactNode } from 'react';

type BadgeVariant = 'default' | 'success' | 'danger' | 'warning' | 'info' | 'orange' | 'violet';

interface BadgeProps {
  variant?: BadgeVariant;
  children: ReactNode;
  className?: string;
}

export function Badge({ variant = 'default', children, className = '' }: BadgeProps) {
  const variants: Record<BadgeVariant, string> = {
    default: 'bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300',
    success: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400',
    danger:  'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400',
    warning: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400',
    info:    'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400',
    orange:  'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400',
    violet:  'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-400',
  };
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold whitespace-nowrap ${variants[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
