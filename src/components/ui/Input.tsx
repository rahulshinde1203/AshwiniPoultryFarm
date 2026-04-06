import { InputHTMLAttributes, SelectHTMLAttributes, ReactNode } from 'react';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
}

export function Input({ label, className = '', ...props }: InputProps) {
  return (
    <div className="w-full">
      {label && (
        <label className="block text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wide mb-1.5">
          {label}
        </label>
      )}
      <input
        className={`
          w-full border border-gray-200 dark:border-slate-600 rounded-xl
          px-3 py-2.5 text-sm
          bg-white dark:bg-slate-800
          text-gray-900 dark:text-slate-100
          placeholder:text-gray-400 dark:placeholder:text-slate-500
          focus:outline-none focus:ring-2 focus:ring-orange-400
          transition-all ${className}
        `}
        {...props}
      />
    </div>
  );
}

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  children: ReactNode;
}

export function Select({ label, className = '', children, ...props }: SelectProps) {
  return (
    <div className="w-full">
      {label && (
        <label className="block text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wide mb-1.5">
          {label}
        </label>
      )}
      <select
        className={`
          w-full border border-gray-200 dark:border-slate-600 rounded-xl
          px-3 py-2.5 text-sm
          bg-white dark:bg-slate-800
          text-gray-900 dark:text-slate-100
          focus:outline-none focus:ring-2 focus:ring-orange-400
          transition-all ${className}
        `}
        {...props}
      >
        {children}
      </select>
    </div>
  );
}
