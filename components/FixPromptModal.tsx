'use client';

import { useEffect, useRef } from 'react';

interface FixPromptModalProps {
  isOpen: boolean;
  onClose: () => void;
  checkName: string;
  headline: string;
  prompt: string;
  warning: string;
}

export default function FixPromptModal({
  isOpen,
  onClose,
  checkName,
  headline,
  prompt,
  warning,
}: FixPromptModalProps) {
  const copied = useRef(false);

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', handleKey);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  function handleCopy() {
    navigator.clipboard.writeText(prompt).then(() => {
      copied.current = true;
      // Force re-render
      const btn = document.getElementById('copy-btn');
      if (btn) {
        btn.textContent = '✓ Copied!';
        btn.classList.add('bg-green-500');
        btn.classList.remove('bg-orange-500', 'hover:bg-orange-600');
        setTimeout(() => {
          btn.textContent = 'Copy prompt';
          btn.classList.remove('bg-green-500');
          btn.classList.add('bg-orange-500', 'hover:bg-orange-600');
        }, 2000);
      }
    });
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-white rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b border-slate-100">
          <div>
            <p className="text-xs text-slate-400 font-medium uppercase tracking-wide mb-1">{checkName}</p>
            <h2 id="modal-title" className="text-xl font-semibold text-slate-900 leading-snug">
              Fix: {headline}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="ml-4 p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-lg transition-colors flex-shrink-0"
            aria-label="Close modal"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6 6 18M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-5">
          {/* Warning box */}
          <div className="flex gap-3 bg-amber-50 border border-amber-200 rounded-xl p-4">
            <span className="text-xl flex-shrink-0">⚠️</span>
            <div>
              <p className="font-semibold text-amber-800 text-sm mb-1">Before you apply this fix</p>
              <p className="text-amber-700 text-sm leading-relaxed">{warning}</p>
            </div>
          </div>

          {/* How to use */}
          <div className="bg-slate-50 rounded-xl p-4">
            <p className="text-sm font-medium text-slate-700 mb-2">How to use this prompt</p>
            <ol className="text-sm text-slate-500 space-y-1 list-decimal list-inside leading-relaxed">
              <li>Copy the prompt below</li>
              <li>Open Lovable, Cursor, Bolt, or ChatGPT</li>
              <li>Paste the prompt and send it</li>
              <li>Apply the suggested change</li>
              <li>Test your app before moving to the next fix</li>
            </ol>
          </div>

          {/* The prompt */}
          <div>
            <p className="text-sm font-medium text-slate-700 mb-2">Your fix prompt</p>
            <div className="bg-slate-900 rounded-xl p-5 font-mono text-sm text-slate-100 leading-relaxed whitespace-pre-wrap break-words">
              {prompt}
            </div>
          </div>

          {/* Copy button */}
          <button
            id="copy-btn"
            onClick={handleCopy}
            className="w-full py-3 bg-orange-500 hover:bg-orange-600 text-white font-semibold rounded-xl transition-colors text-base"
          >
            Copy prompt
          </button>

          {/* Fine print */}
          <p className="text-xs text-slate-400 text-center leading-relaxed">
            Always test your app after each change. Apply fixes one at a time.
            VibeScan is not responsible for changes made using these prompts.
          </p>
        </div>
      </div>
    </div>
  );
}
