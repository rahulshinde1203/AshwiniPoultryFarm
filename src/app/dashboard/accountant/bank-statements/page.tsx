'use client';
import { useEffect, useRef, useState } from 'react';
import { useSyncStream } from '@/hooks/useSyncStream';
import { toast } from 'sonner';

type PeriodType = 'all' | 'day' | 'month' | 'range';

const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
const YEARS  = Array.from({ length: 5 }, (_, i) => new Date().getFullYear() - i);
const fmt    = (n: number | null | undefined) => `₹${(n ?? 0).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
const fmtDate = (iso: string) => new Date(iso).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
const inp    = 'w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-orange-400 bg-white';
const lbl    = 'block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5';
const todayStr = () => new Date().toISOString().split('T')[0];

const SOURCE_LABEL: Record<string, { label: string; color: string }> = {
  manual:          { label: 'Manual',          color: 'bg-gray-100 text-gray-700' },
  opening_balance: { label: 'Opening Balance', color: 'bg-blue-100 text-blue-700' },
  payment_trader:  { label: 'Trader Payment',  color: 'bg-green-100 text-green-700' },
  payment_company: { label: 'Company Payment', color: 'bg-red-100 text-red-700' },
  expense:         { label: 'Expense',         color: 'bg-purple-100 text-purple-700' },
};

const PERIOD_LABELS: Record<PeriodType, string> = {
  all: 'All Time', day: 'Select Date', month: 'Select Month', range: 'Date Range',
};


export default function AccountantBankStatementsPage() {
  const [statements,     setStatements]     = useState<any[]>([]);
  const [openingBalance, setOpeningBalance] = useState<number | null>(null);
  const [closingBalance, setClosingBalance] = useState<number>(0);
  const [accounts,       setAccounts]       = useState<any[]>([]);
  const [selAccount,     setSelAccount]     = useState('');
  const [period,         setPeriod]         = useState<PeriodType>('month');
  const [selDate,        setSelDate]        = useState(todayStr());
  const [selMonth,       setSelMonth]       = useState(new Date().getMonth() + 1);
  const [selYear,        setSelYear]        = useState(new Date().getFullYear());
  const [rangeStart,     setRangeStart]     = useState('');
  const [rangeEnd,       setRangeEnd]       = useState('');
  const [showForm,       setShowForm]       = useState(false);
  const [submitting,     setSubmitting]     = useState(false);
  const [lastUpdated,    setLastUpdated]    = useState<Date | null>(null);
  const [form, setForm] = useState({
    bankAccount: '', date: todayStr(), description: '', remark: '',
    credit: '', debit: '', transactionId: '', type: 'credit' as 'credit' | 'debit',
  });

  const filterRef = useRef({ period, selAccount, selDate, selMonth, selYear, rangeStart, rangeEnd });
  useEffect(() => { filterRef.current = { period, selAccount, selDate, selMonth, selYear, rangeStart, rangeEnd }; });

  const buildParams = (f = filterRef.current) => {
    const p = new URLSearchParams({ period: f.period });
    if (f.selAccount) p.set('bankAccount', f.selAccount);
    if (f.period === 'day')   p.set('date', f.selDate);
    if (f.period === 'month') { p.set('month', String(f.selMonth)); p.set('year', String(f.selYear)); }
    if (f.period === 'range') { p.set('start', f.rangeStart); p.set('end', f.rangeEnd); }
    return p.toString();
  };

  const loadStatements = (silent = false) => {
    const f = filterRef.current;
    if (f.period === 'range' && (!f.rangeStart || !f.rangeEnd)) return;
    fetch(`/api/bank-statements?${buildParams(f)}`)
      .then(r => r.json())
      .then(d => {
        setStatements(d.statements || []);
        setOpeningBalance(d.openingBalance ?? null);
        setClosingBalance(d.closingBalance ?? 0);
        if (!silent) setLastUpdated(new Date());
      });
  };

  const load = () => {
    fetch('/api/bank-accounts').then(r => r.json()).then(d => {
      const accs = d.accounts || [];
      setAccounts(accs);
      if (accs.length && !filterRef.current.selAccount) setSelAccount(accs[0]._id);
    });
    loadStatements();
  };

  useEffect(() => { load(); }, []);
  useEffect(() => { loadStatements(); }, [period, selDate, selMonth, selYear, rangeStart, rangeEnd, selAccount]);
  useEffect(() => {
    const onVisible = () => { if (document.visibilityState === 'visible') loadStatements(true); };
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('focus', onVisible);
    return () => {
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener('focus', onVisible);
    };
  }, []);

  useSyncStream(['payment', 'expense'], () => loadStatements(true));

  // Newest first for display; use `s.balance` from API (already correct running balance)
  const filtered      = [...statements].reverse();
  const totalCredit   = statements.reduce((s, x) => s + (x.creditAmount || 0), 0);
  const totalDebit    = statements.reduce((s, x) => s + (x.debitAmount  || 0), 0);
  const hasOpeningBal = openingBalance !== null;

  const periodLabel = period === 'all' ? 'All-Time'
    : period === 'day'   ? selDate
    : period === 'month' ? `${MONTHS[selMonth - 1]}-${selYear}`
    : rangeStart && rangeEnd ? `${rangeStart}-to-${rangeEnd}` : 'Range';

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    const payload = {
      bankAccount:   form.bankAccount || selAccount,
      date:          form.date,
      description:   form.description,
      remark:        form.remark,
      transactionId: form.transactionId,
      creditAmount:  form.type === 'credit' ? form.credit : '0',
      debitAmount:   form.type === 'debit'  ? form.debit  : '0',
    };
    const res  = await fetch('/api/bank-statements', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    });
    const data = await res.json();
    setSubmitting(false);
    if (res.ok) {
      toast.success('Entry added');
      setShowForm(false);
      setForm({ bankAccount: '', date: todayStr(), description: '', remark: '', credit: '', debit: '', transactionId: '', type: 'credit' });
      loadStatements();
    } else toast.error(data.error || 'Failed');
  };

  const exportExcel = async () => {
    if (!filtered.length && !hasOpeningBal) return;
    const { utils, writeFile } = await import('xlsx');
    const rows: any[] = [];
    // Closing balance at top in export too
    rows.push({ '#': '—', 'Date': '—', 'Account': '—', 'Description': 'Closing Balance (end of period)', 'Remark': '', 'Transaction ID': '', 'Type': '', 'Credit (₹)': '', 'Debit (₹)': '', 'Balance (₹)': closingBalance });
    filtered.forEach((s, i) => rows.push({
      '#': i + 1,
      'Date': fmtDate(s.date),
      'Account': s.bankAccount?.bankName || '',
      'Description': s.description || '',
      'Remark': s.remark || '',
      'Transaction ID': s.transactionId || '',
      'Type': SOURCE_LABEL[s.sourceType]?.label || s.sourceType,
      'Credit (₹)': s.creditAmount > 0 ? s.creditAmount : '',
      'Debit (₹)':  s.debitAmount  > 0 ? s.debitAmount  : '',
      'Balance (₹)': s.balance ?? 0,
    }));
    if (hasOpeningBal) {
      rows.push({ '#': '—', 'Date': '—', 'Account': '—', 'Description': 'Opening Balance (brought forward)', 'Remark': '', 'Transaction ID': '', 'Type': 'Opening Balance', 'Credit (₹)': '', 'Debit (₹)': '', 'Balance (₹)': openingBalance });
    }
    const wb = utils.book_new();
    utils.book_append_sheet(wb, utils.json_to_sheet(rows), 'Bank Statement');
    const acct = accounts.find(a => a._id === selAccount);
    writeFile(wb, `bank-statement-${acct?.bankName?.replace(/\s+/g, '-') || 'account'}-${periodLabel}.xlsx`);
    toast.success('Excel downloaded!');
  };

  return (
    <div className="min-h-screen bg-gray-50">

      {/* Header */}
      <div className="bg-gradient-to-r from-slate-700 to-gray-800 px-5 sm:px-8 py-6">
        <div className="max-w-6xl mx-auto flex items-start justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-white font-extrabold text-xl sm:text-2xl">Bank Statements</h1>
            <p className="text-slate-300 text-sm mt-0.5">
              {periodLabel.replace(/-/g, ' ')} · {filtered.length} entries
              {lastUpdated && <span className="text-slate-400"> · {lastUpdated.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}</span>}
            </p>
          </div>
          <div className="flex gap-2 flex-wrap">
            <button onClick={exportExcel} disabled={!filtered.length && !hasOpeningBal}
              className="px-3 py-2 bg-green-600 text-white rounded-xl text-xs font-semibold hover:bg-green-700 disabled:opacity-40 transition">
              📥 Excel
            </button>
            <button onClick={() => setShowForm(s => !s)}
              className="px-4 py-2 bg-orange-500 text-white rounded-xl text-sm font-semibold hover:bg-orange-600 transition shadow-sm">
              {showForm ? '✕ Cancel' : '+ Manual Entry'}
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-5 space-y-4">

        {/* Filter Bar */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-4 space-y-4">
          <div className="flex items-start gap-3 flex-wrap">
            <div className="flex flex-col gap-1 shrink-0">
              <span className="text-xs font-bold text-gray-400 uppercase tracking-wide">Period</span>
              <div className="flex gap-0.5 bg-gray-100 rounded-xl p-1">
                {(['all', 'day', 'month', 'range'] as PeriodType[]).map(p => (
                  <button key={p} onClick={() => setPeriod(p)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${period === p ? 'bg-orange-500 text-white shadow-sm' : 'text-gray-500 hover:text-gray-800'}`}>
                    {PERIOD_LABELS[p]}
                  </button>
                ))}
              </div>
            </div>
            {period === 'day' && (
              <div className="flex flex-col gap-1">
                <span className="text-xs font-bold text-gray-400 uppercase tracking-wide">Date</span>
                <input type="date" value={selDate} max={todayStr()} onChange={e => setSelDate(e.target.value)}
                  className="border border-gray-200 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-400 bg-white" />
              </div>
            )}
            {period === 'month' && (
              <div className="flex items-end gap-2">
                <div className="flex flex-col gap-1">
                  <span className="text-xs font-bold text-gray-400 uppercase tracking-wide">Month</span>
                  <select value={selMonth} onChange={e => setSelMonth(Number(e.target.value))}
                    className="border border-gray-200 rounded-xl px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-orange-400">
                    {MONTHS.map((m, i) => <option key={m} value={i + 1}>{m}</option>)}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-xs font-bold text-gray-400 uppercase tracking-wide">Year</span>
                  <select value={selYear} onChange={e => setSelYear(Number(e.target.value))}
                    className="border border-gray-200 rounded-xl px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-orange-400">
                    {YEARS.map(y => <option key={y} value={y}>{y}</option>)}
                  </select>
                </div>
              </div>
            )}
            {period === 'range' && (
              <div className="flex items-end gap-2 flex-wrap">
                <div className="flex flex-col gap-1">
                  <span className="text-xs font-bold text-gray-400 uppercase tracking-wide">From</span>
                  <input type="date" value={rangeStart} max={todayStr()} onChange={e => setRangeStart(e.target.value)}
                    className="border border-gray-200 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-400 bg-white" />
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-xs font-bold text-gray-400 uppercase tracking-wide">To</span>
                  <input type="date" value={rangeEnd} max={todayStr()} onChange={e => setRangeEnd(e.target.value)}
                    className="border border-gray-200 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-400 bg-white" />
                </div>
              </div>
            )}
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-xs font-bold text-gray-400 uppercase tracking-wide">🏦 Bank Account</span>
            <select value={selAccount} onChange={e => setSelAccount(e.target.value)}
              className="border border-gray-200 rounded-xl px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-orange-400 min-w-[200px] max-w-xs">
              {accounts.map(a => <option key={a._id} value={a._id}>{a.bankName} — ****{a.accountNumber?.slice(-4)}</option>)}
            </select>
          </div>
        </div>

        {/* Summary Cards */}
        <div className={`grid gap-3 ${hasOpeningBal ? 'grid-cols-2 sm:grid-cols-4' : 'grid-cols-3'}`}>
          <div className={`border rounded-xl p-3 text-center ${closingBalance >= 0 ? 'bg-blue-50 border-blue-200' : 'bg-orange-50 border-orange-200'}`}>
            <p className="text-xs text-gray-500 mb-1">Closing Balance</p>
            <p className={`font-extrabold ${closingBalance >= 0 ? 'text-blue-700' : 'text-orange-600'}`}>{fmt(closingBalance)}</p>
            <p className="text-xs text-gray-400 mt-0.5">End of period</p>
          </div>
          <div className="bg-green-50 border border-green-200 rounded-xl p-3 text-center">
            <p className="text-xs text-gray-500 mb-1">Total Credit</p>
            <p className="font-extrabold text-green-700">{fmt(totalCredit)}</p>
            <p className="text-xs text-green-400 mt-0.5">Money in</p>
          </div>
          <div className="bg-red-50 border border-red-200 rounded-xl p-3 text-center">
            <p className="text-xs text-gray-500 mb-1">Total Debit</p>
            <p className="font-extrabold text-red-600">{fmt(totalDebit)}</p>
            <p className="text-xs text-red-400 mt-0.5">Money out</p>
          </div>
          {hasOpeningBal && (
            <div className="bg-gray-50 border border-gray-200 rounded-xl p-3 text-center">
              <p className="text-xs text-gray-500 mb-1">Opening Balance</p>
              <p className={`font-extrabold text-sm ${(openingBalance ?? 0) >= 0 ? 'text-gray-700' : 'text-orange-600'}`}>
                {fmt(openingBalance)}
              </p>
              <p className="text-xs text-gray-400 mt-0.5">Before period</p>
            </div>
          )}
        </div>

        {/* Manual Entry Form */}
        {showForm && (
          <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
            <div className="bg-gray-50 border-b border-gray-100 px-5 py-3">
              <h3 className="font-bold text-gray-900 text-sm">➕ Manual Entry</h3>
            </div>
            <form onSubmit={submit} className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className={lbl}>Bank Account *</label>
                <select required value={form.bankAccount || selAccount}
                  onChange={e => setForm({ ...form, bankAccount: e.target.value })} className={inp}>
                  <option value="">Select account…</option>
                  {accounts.map(a => <option key={a._id} value={a._id}>{a.bankName} — ****{a.accountNumber?.slice(-4)}</option>)}
                </select>
              </div>
              <div>
                <label className={lbl}>Date *</label>
                <input type="date" required value={form.date} max={todayStr()}
                  onChange={e => setForm({ ...form, date: e.target.value })} className={inp} />
              </div>
              <div>
                <label className={lbl}>Type *</label>
                <div className="flex gap-2">
                  {(['credit', 'debit'] as const).map(t => (
                    <button key={t} type="button" onClick={() => setForm(f => ({ ...f, type: t }))}
                      className={`flex-1 py-2.5 rounded-xl text-sm font-bold border-2 transition ${form.type === t ? (t === 'credit' ? 'bg-green-500 text-white border-green-500' : 'bg-red-500 text-white border-red-500') : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'}`}>
                      {t === 'credit' ? '💰 Credit (In)' : '💸 Debit (Out)'}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className={lbl}>Amount (₹) *</label>
                <input required type="number" min="0.01" step="0.01"
                  value={form.type === 'credit' ? form.credit : form.debit}
                  onChange={e => setForm(f => ({ ...f, [f.type === 'credit' ? 'credit' : 'debit']: e.target.value }))}
                  className={inp} placeholder="0.00" />
              </div>
              <div className="sm:col-span-2">
                <label className={lbl}>Description *</label>
                <input required value={form.description}
                  onChange={e => setForm({ ...form, description: e.target.value })}
                  className={inp} placeholder="e.g. Cash withdrawal, Bank charges…" />
              </div>
              <div>
                <label className={lbl}>Remark <span className="text-gray-400 font-normal normal-case">(optional)</span></label>
                <input value={form.remark} onChange={e => setForm({ ...form, remark: e.target.value })}
                  className={inp} placeholder="Additional context…" />
              </div>
              <div>
                <label className={lbl}>Transaction ID <span className="text-gray-400 font-normal normal-case">(optional)</span></label>
                <input value={form.transactionId} onChange={e => setForm({ ...form, transactionId: e.target.value })}
                  className={inp} placeholder="UTR / Ref number" />
              </div>
              <div className="sm:col-span-2 flex gap-3">
                <button type="submit" disabled={submitting}
                  className="flex-1 sm:flex-none px-6 py-2.5 bg-orange-500 text-white rounded-xl font-bold text-sm disabled:opacity-50 hover:bg-orange-600 transition">
                  {submitting ? 'Saving…' : '➕ Add Entry'}
                </button>
                <button type="button" onClick={() => setShowForm(false)}
                  className="px-5 py-2.5 border border-gray-200 rounded-xl text-sm hover:bg-gray-50">Cancel</button>
              </div>
            </form>
          </div>
        )}

        {/* Table */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">

          {/* Mobile */}
          <div className="sm:hidden">
            {/* Closing Balance at TOP */}
            <div className="bg-blue-600 px-4 py-3 flex items-center justify-between">
              <div>
                <p className="text-xs font-bold text-white">📁 Closing Balance</p>
                <p className="text-xs text-blue-200 mt-0.5">End of period</p>
              </div>
              <p className="font-extrabold text-white text-base">{fmt(closingBalance)}</p>
            </div>
            <div className="divide-y divide-gray-50">
              {filtered.map(s => (
                <div key={s._id} className="px-4 py-3.5">
                  <div className="flex items-start justify-between mb-1">
                    <div className="flex-1 min-w-0 mr-3">
                      <p className="font-semibold text-gray-900 text-sm truncate">{s.description}</p>
                      {s.remark && <p className="text-xs text-blue-600 mt-0.5">📌 {s.remark}</p>}
                      <p className="text-xs text-gray-400 mt-0.5">{fmtDate(s.date)} · {s.bankAccount?.bankName}</p>
                    </div>
                    <div className="text-right shrink-0">
                      {s.creditAmount > 0 && <p className="font-bold text-green-600">+{fmt(s.creditAmount)}</p>}
                      {s.debitAmount  > 0 && <p className="font-bold text-red-600">−{fmt(s.debitAmount)}</p>}
                      <p className={`text-xs font-bold mt-0.5 ${(s.balance ?? 0) >= 0 ? 'text-blue-700' : 'text-orange-600'}`}>
                        Bal: {fmt(s.balance)}
                      </p>
                    </div>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${SOURCE_LABEL[s.sourceType]?.color || 'bg-gray-100 text-gray-600'}`}>
                    {SOURCE_LABEL[s.sourceType]?.label || s.sourceType}
                  </span>
                </div>
              ))}
              {filtered.length === 0 && (
                <div className="py-14 text-center text-gray-400">
                  <div className="text-3xl mb-2">🏦</div>
                  <p className="text-sm">{hasOpeningBal ? 'No transactions in this period' : 'No entries found'}</p>
                </div>
              )}
            </div>
            {/* Opening Balance at BOTTOM */}
            {hasOpeningBal && (
              <div className="bg-blue-50 border-t-2 border-blue-200 px-4 py-3 flex items-center justify-between">
                <div>
                  <p className="text-xs font-bold text-blue-700">📂 Opening Balance</p>
                  <p className="text-xs text-blue-400 mt-0.5">Brought forward</p>
                </div>
                <p className="font-extrabold text-blue-700">{fmt(openingBalance)}</p>
              </div>
            )}
          </div>

          {/* Desktop */}
          <div className="hidden sm:block overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-200 sticky top-0 z-10">
                <tr>
                  {['#', 'Date', 'Account', 'Description', 'Remark', 'Txn ID', 'Type', 'Credit', 'Debit', 'Balance'].map(h => (
                    <th key={h} className="text-left text-xs font-semibold text-gray-500 uppercase px-4 py-3 whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">

                {/* ── Closing Balance at TOP ── */}
                <tr className="bg-blue-600 border-b-2 border-blue-700">
                  <td className="px-4 py-3 text-xs font-bold text-blue-200">—</td>
                  <td className="px-4 py-3 text-xs font-bold text-white whitespace-nowrap">
                    {period === 'month'
                      ? `${new Date(selYear, selMonth, 0).getDate()} ${MONTHS[selMonth - 1].slice(0, 3)} ${selYear}`
                      : period === 'day' ? fmtDate(selDate + 'T00:00:00')
                      : period === 'range' && rangeEnd ? fmtDate(rangeEnd + 'T00:00:00')
                      : 'Latest'}
                  </td>
                  <td colSpan={7} className="px-4 py-3 text-xs font-bold text-blue-100">
                    📁 Closing Balance (end of period)
                  </td>
                  <td className="px-4 py-3 font-extrabold text-white whitespace-nowrap text-base">
                    {fmt(closingBalance)}
                  </td>
                </tr>

                {/* Transaction rows */}
                {filtered.map((s, i) => (
                  <tr key={s._id} className="hover:bg-gray-50/80 transition">
                    <td className="px-4 py-3 text-xs text-gray-400">{i + 1}</td>
                    <td className="px-4 py-3 text-xs text-gray-600 whitespace-nowrap">{fmtDate(s.date)}</td>
                    <td className="px-4 py-3 text-xs text-gray-600">{s.bankAccount?.bankName}</td>
                    <td className="px-4 py-3 text-xs font-medium text-gray-800">{s.description}</td>
                    <td className="px-4 py-3 text-xs text-blue-700 max-w-[160px]">
                      {s.remark ? <span>📌 {s.remark}</span> : <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-gray-500">{s.transactionId || '—'}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${SOURCE_LABEL[s.sourceType]?.color || 'bg-gray-100 text-gray-600'}`}>
                        {SOURCE_LABEL[s.sourceType]?.label || s.sourceType}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-green-600 whitespace-nowrap">
                      {s.creditAmount > 0 ? `+${fmt(s.creditAmount)}` : <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-4 py-3 font-semibold text-red-600 whitespace-nowrap">
                      {s.debitAmount > 0 ? `−${fmt(s.debitAmount)}` : <span className="text-gray-300">—</span>}
                    </td>
                    <td className={`px-4 py-3 font-bold whitespace-nowrap ${(s.balance ?? 0) >= 0 ? 'text-blue-700' : 'text-orange-600'}`}>
                      {fmt(s.balance)}
                    </td>
                  </tr>
                ))}

                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={10} className="py-14 text-center text-gray-400 bg-white">
                      <div className="text-3xl mb-2">🏦</div>
                      <p>{hasOpeningBal ? 'No transactions in this period' : 'No entries found'}</p>
                    </td>
                  </tr>
                )}
              </tbody>

              {/* ── Totals + Opening Balance at BOTTOM ── */}
              <tfoot>
                {filtered.length > 0 && (
                  <tr className="bg-gray-50 border-t border-gray-200">
                    <td colSpan={7} className="px-4 py-3 text-xs font-extrabold text-gray-600 uppercase">
                      Totals ({filtered.length} entries)
                    </td>
                    <td className="px-4 py-3 font-extrabold text-green-700">+{fmt(totalCredit)}</td>
                    <td className="px-4 py-3 font-extrabold text-red-600">−{fmt(totalDebit)}</td>
                    <td className="px-4 py-3 font-extrabold text-gray-500">{fmt(closingBalance)}</td>
                  </tr>
                )}
                {hasOpeningBal && (
                  <tr className="bg-blue-50 border-t-2 border-blue-200">
                    <td className="px-4 py-3 text-xs font-bold text-blue-400">—</td>
                    <td className="px-4 py-3 text-xs font-bold text-blue-600 whitespace-nowrap">
                      {period === 'month'
                        ? `01 ${MONTHS[selMonth - 1].slice(0, 3)} ${selYear}`
                        : period === 'day' ? fmtDate(selDate + 'T00:00:00')
                        : period === 'range' && rangeStart ? fmtDate(rangeStart + 'T00:00:00')
                        : '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-blue-500">
                      {accounts.find(a => a._id === selAccount)?.bankName || '—'}
                    </td>
                    <td className="px-4 py-3 text-xs font-bold text-blue-700" colSpan={4}>
                      📂 Opening Balance (brought forward)
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-300">—</td>
                    <td className="px-4 py-3 text-xs text-gray-300">—</td>
                    <td className="px-4 py-3 font-extrabold text-blue-700 whitespace-nowrap">
                      {fmt(openingBalance)}
                    </td>
                  </tr>
                )}
              </tfoot>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
