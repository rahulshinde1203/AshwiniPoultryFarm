import { ReactNode } from 'react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  className?: string;
  maxWidth?: string;
}

export function Modal({
  open,
  onClose,
  children,
  className = '',
  maxWidth = 'max-w-md',
}: ModalProps) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className={`
          bg-white dark:bg-[#0F172A]
          rounded-2xl shadow-2xl w-full ${maxWidth}
          border border-gray-100 dark:border-slate-700/50
          ${className}
        `}
        onClick={e => e.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
}
