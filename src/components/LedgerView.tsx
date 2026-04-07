'use client';
import { useState, useEffect } from 'react';
import { toast } from 'sonner';

type PartyType  = 'trader' | 'company';
type PeriodType = 'all' | 'day' | 'month' | 'range';

const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
const YEARS  = Array.from({ length: 5 }, (_, i) => new Date().getFullYear() - i);

const fmtAmt  = (n: number | null) => n == null ? '' : `₹${Math.abs(n).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
const fmtNum  = (n: number | null) => n == null ? '' : n.toLocaleString('en-IN');
const fmtWt   = (n: number | null) => n == null ? '' : n.toFixed(3);
const fmtBal  = (n: number) => {
  const abs = Math.abs(n).toLocaleString('en-IN', { minimumFractionDigits: 2 });
  if (n > 0.01)  return { text: `₹${abs}`, color: 'text-red-600',   label: 'DR' };
  if (n < -0.01) return { text: `₹${abs}`, color: 'text-green-600', label: 'CR' };
  return { text: '₹0.00', color: 'text-gray-500', label: 'NIL' };
};
const fmtDate = (iso: string) => new Date(iso).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });

const inp = 'border border-gray-200 rounded-xl px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-orange-400';

export default function LedgerView() {
  const [partyType,  setPartyType]  = useState<PartyType>('trader');
  const [partyId,    setPartyId]    = useState('');
  const [period,     setPeriod]     = useState<PeriodType>('all');
  const [selDate,    setSelDate]    = useState(new Date().toISOString().split('T')[0]);
  const [selMonth,   setSelMonth]   = useState(new Date().getMonth() + 1);
  const [selYear,    setSelYear]    = useState(new Date().getFullYear());
  const [rangeStart, setRangeStart] = useState('');
  const [rangeEnd,   setRangeEnd]   = useState('');

  const [rows,       setRows]       = useState<any[]>([]);
  const [partyName,  setPartyName]  = useState('');
  const [finalBal,   setFinalBal]   = useState(0);
  const [traders,    setTraders]    = useState<any[]>([]);
  const [companies,  setCompanies]  = useState<any[]>([]);
  const [loading,    setLoading]    = useState(false);
  const [generated,  setGenerated]  = useState(false);
  const [dropdownLoading, setDropdownLoading] = useState(true);

  useEffect(() => {
    setDropdownLoading(true);
    Promise.all([
      fetch('/api/ledger?partyType=trader&partyId=0&period=all').then(r=>r.json()),
      fetch('/api/ledger?partyType=company&partyId=0&period=all').then(r=>r.json()),
    ]).then(([td, cd]) => {
      setTraders(td.traders || []);
      setCompanies(cd.companies || []);
    }).catch(() => {}).finally(() => setDropdownLoading(false));
  }, []);

  const buildQS = () => {
    const p = new URLSearchParams({ partyType, period });
    if (partyId) p.set('partyId', partyId);
    if (period === 'day')   p.set('date', selDate);
    if (period === 'month') { p.set('month', String(selMonth)); p.set('year', String(selYear)); }
    if (period === 'range') { p.set('start', rangeStart); p.set('end', rangeEnd); }
    return p.toString();
  };

  const generate = async () => {
    if (!partyId) { toast.error('Please select a party'); return; }
    if (period === 'range' && (!rangeStart || !rangeEnd)) { toast.error('Select both start and end dates'); return; }
    setLoading(true);
    try {
      const res = await fetch(`/api/ledger?${buildQS()}`);
      const d   = await res.json();
      if (!res.ok) { toast.error(d.error || 'Failed to generate report'); return; }
      setRows(d.rows || []);
      setPartyName(d.partyName || '');
      setFinalBal(d.finalBalance ?? 0);
      setGenerated(true);
    } catch { toast.error('Network error — could not load ledger'); }
    finally  { setLoading(false); }
  };

  const reset = () => {
    setRows([]); setPartyId(''); setGenerated(false); setFinalBal(0); setPartyName('');
  };

  const periodLabel = period === 'all' ? 'All Time'
    : period === 'day'   ? fmtDate(selDate + 'T00:00:00')
    : period === 'month' ? `${MONTHS[selMonth-1]} ${selYear}`
    : `${rangeStart} to ${rangeEnd}`;

  /* ── Export CSV ── */
  const exportCSV = () => {
    if (!rows.length) return;
    const isTrader = partyType === 'trader';
    const headers = ['#','Date','Type','Vehicle No','Birds','Weight (Kg)','Avg Weight','Rate/Kg',
      'Total Amount', isTrader ? 'Credit Amount' : 'Debit Amount',
      'Method','Transaction ID','Closing Balance','DR/CR'];

    const dataRows = rows.map((r, i) => [
      i + 1,
      fmtDate(r.date),
      r.rowType === 'opening' ? 'Opening Balance' : r.rowType === 'txn' ? 'Transaction' : 'Payment',
      r.vehicleNumber || '',
      r.numberOfBirds != null ? r.numberOfBirds : '',
      r.totalWeight   != null ? r.totalWeight.toFixed(3) : '',
      r.avgWeight     != null ? r.avgWeight.toFixed(3) : '',
      r.rate          != null ? r.rate : '',
      r.totalAmount   != null ? r.totalAmount : '',
      r.creditDebitAmt != null ? r.creditDebitAmt : '',
      r.paymentMethod || '',
      r.transactionId || '',
      Math.abs(r.closingBalance).toFixed(2),
      r.closingBalance > 0.01 ? 'DR' : r.closingBalance < -0.01 ? 'CR' : 'NIL',
    ]);

    const csv = [headers, ...dataRows]
      .map(row => row.map(v => `"${String(v).replace(/"/g,'""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${partyType}-ledger-${partyName.replace(/\s/g,'-')}-${periodLabel.replace(/\s/g,'-')}.csv`;
    a.click();
    toast.success('CSV downloaded!');
  };

  /* ── Export PDF ── */
  const exportPDF = async () => {
    if (!rows.length) return;
    try {
      const { default: jsPDF }     = await import('jspdf');
      const { default: autoTable } = await import('jspdf-autotable');
      const isTrader = partyType === 'trader';
      const doc = new jsPDF({ orientation: 'landscape' });

      doc.setFontSize(18); doc.setTextColor(249, 115, 22);
      doc.text('Ashwini Poultry Farm', 14, 16);
      doc.setTextColor(0, 0, 0);
      doc.setFontSize(13); doc.text(`${isTrader ? 'Trader' : 'Company'} Ledger Statement`, 14, 24);
      doc.setFontSize(9);
      doc.text(`Party: ${partyName}`, 14, 31);
      doc.text(`Period: ${periodLabel}`, 14, 37);
      doc.text(`Generated: ${new Date().toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' })}`, 14, 43);

      const finalB = fmtBal(finalBal);
      doc.setFontSize(10);
      doc.setTextColor(finalBal > 0.01 ? 220 : 22, finalBal > 0.01 ? 38 : 163, finalBal > 0.01 ? 38 : 74);
      doc.text(`Closing Balance: Rs.${Math.abs(finalBal).toLocaleString('en-IN', { minimumFractionDigits: 2 })} ${finalB.label}`, 14, 51);
      doc.setTextColor(0, 0, 0);

      const head = [['#','Date','Type','Vehicle','Birds','Wt(Kg)','Avg Wt','Rate',
        'Total Amt', isTrader ? 'Credit' : 'Debit', 'Method','Txn ID','Balance','']];

      const body = rows.map((r, i) => {
        const b = fmtBal(r.closingBalance);
        return [
          i + 1,
          fmtDate(r.date),
          r.rowType === 'opening' ? 'Opening Bal' : r.rowType === 'txn' ? 'Transaction' : 'Payment',
          r.vehicleNumber || '—',
          r.numberOfBirds != null ? r.numberOfBirds.toLocaleString('en-IN') : '—',
          r.totalWeight   != null ? r.totalWeight.toFixed(3) : '—',
          r.avgWeight     != null ? r.avgWeight.toFixed(3) : '—',
          r.rate          != null ? `Rs.${r.rate}` : '—',
          r.totalAmount   != null ? `Rs.${r.totalAmount.toLocaleString('en-IN', { minimumFractionDigits: 2 })}` : '—',
          r.creditDebitAmt != null ? `Rs.${r.creditDebitAmt.toLocaleString('en-IN', { minimumFractionDigits: 2 })}` : '—',
          r.paymentMethod || '—',
          r.transactionId || '—',
          `Rs.${Math.abs(r.closingBalance).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`,
          b.label,
        ];
      });

      autoTable(doc, {
        startY: 56, head, body,
        styles: { fontSize: 7.5 },
        headStyles: { fillColor: [249, 115, 22], textColor: 255 },
        didParseCell: (data: any) => {
          if (data.section === 'body') {
            const row = rows[data.row.index];
            if (!row) return;
            // Style closing balance column
            if (data.column.index === 13) {
              data.cell.styles.textColor = row.closingBalance > 0.01 ? [220, 38, 38] : row.closingBalance < -0.01 ? [22, 163, 74] : [107, 114, 128];
              data.cell.styles.fontStyle = 'bold';
            }
            // Style opening balance row
            if (row.rowType === 'opening') {
              data.cell.styles.fillColor = [240, 240, 240];
              data.cell.styles.fontStyle = 'bold';
              data.cell.styles.textColor = [50, 50, 50];
            }
            // Shade payment rows
            if (row.rowType === 'payment') {
              data.cell.styles.fillColor = [240, 253, 244];
            }
          }
        },
      });

      doc.save(`${partyType}-ledger-${partyName.replace(/\s/g,'-')}.pdf`);
      toast.success('PDF downloaded!');
    } catch { toast.error('PDF export failed'); }
  };

  const finalBalInfo  = fmtBal(finalBal);
  const txnCount      = rows.filter(r => r.rowType === 'txn').length;
  const payCount      = rows.filter(r => r.rowType === 'payment').length;
  const hasOpening    = rows.length > 0 && rows[0].rowType === 'opening';
  const openingRow    = hasOpening ? rows[0] : null;
  const openingBalInf = openingRow ? fmtBal(openingRow.closingBalance) : null;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-700 to-gray-800 px-5 sm:px-8 py-6">
        <div className="max-w-5xl mx-auto">
          <h1 className="text-white font-extrabold text-xl sm:text-2xl">Ledger Report</h1>
          <p className="text-slate-300 text-sm mt-0.5">Trader / Company account ledger with running balance</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-4 sm:px-6 py-5 space-y-4">

        {/* ── FILTER PANEL ── */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-5 space-y-5">

          {/* Party Type */}
          <div>
            <p className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-2">Party Type</p>
            <div className="flex gap-2">
              {(['trader','company'] as PartyType[]).map(t => (
                <button key={t} onClick={() => { setPartyType(t); setPartyId(''); setGenerated(false); setRows([]); }}
                  className={`px-5 py-2.5 rounded-xl text-sm font-bold border-2 transition ${partyType === t
                    ? t === 'trader' ? 'bg-orange-500 text-white border-orange-500' : 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'}`}>
                  {t === 'trader' ? '🤝 Trader' : '🏭 Company'}
                </button>
              ))}
            </div>
          </div>

          {/* Party Selection */}
          <div>
            <p className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-2">
              Select {partyType === 'trader' ? 'Trader' : 'Company'} *
            </p>
            <select value={partyId} onChange={e => { setPartyId(e.target.value); setGenerated(false); setRows([]); }}
              className={`${inp} min-w-[260px]`} disabled={dropdownLoading}>
              <option value="">{dropdownLoading ? 'Loading…' : `-- Select ${partyType === 'trader' ? 'Trader' : 'Company'} --`}</option>
              {partyType === 'trader'
                ? traders.map(t => <option key={t._id} value={t._id}>{t.name}</option>)
                : companies.map(c => <option key={c._id} value={c._id}>{c.name}</option>)}
            </select>
          </div>

          {/* Period */}
          <div>
            <p className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-2">Date Filter</p>
            <div className="flex flex-wrap gap-2 mb-3">
              {(['all','day','month','range'] as PeriodType[]).map(p => (
                <button key={p} onClick={() => setPeriod(p)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-bold border transition ${period === p ? 'bg-orange-500 text-white border-orange-500 shadow-sm' : 'bg-gray-50 text-gray-600 border-gray-200 hover:border-orange-300'}`}>
                  {p === 'all' ? '📅 All Time' : p === 'day' ? '📆 Select Day' : p === 'month' ? '🗓 Select Month' : '📊 Date Range'}
                </button>
              ))}
            </div>

            {period !== 'all' && (
              <div className="bg-blue-50 border border-blue-200 rounded-xl px-3 py-2 mb-3 text-xs text-blue-700 font-medium">
                📌 Opening balance (previous period closing) will appear as the first row
              </div>
            )}

            {period === 'day' && (
              <input type="date" value={selDate} max={new Date().toISOString().split('T')[0]}
                onChange={e => setSelDate(e.target.value)} className={inp} />
            )}
            {period === 'month' && (
              <div className="flex gap-2">
                <select value={selMonth} onChange={e => setSelMonth(Number(e.target.value))} className={inp}>
                  {MONTHS.map((m, i) => <option key={m} value={i+1}>{m}</option>)}
                </select>
                <select value={selYear} onChange={e => setSelYear(Number(e.target.value))} className={inp}>
                  {YEARS.map(y => <option key={y} value={y}>{y}</option>)}
                </select>
              </div>
            )}
            {period === 'range' && (
              <div className="flex items-center gap-3 flex-wrap">
                <input type="date" value={rangeStart} max={new Date().toISOString().split('T')[0]}
                  onChange={e => setRangeStart(e.target.value)} className={inp} />
                <span className="text-gray-400 text-sm">to</span>
                <input type="date" value={rangeEnd} max={new Date().toISOString().split('T')[0]}
                  onChange={e => setRangeEnd(e.target.value)} className={inp} />
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex gap-3 pt-1">
            <button onClick={generate} disabled={loading || !partyId}
              className="px-6 py-2.5 bg-orange-500 hover:bg-orange-600 text-white rounded-xl font-bold text-sm disabled:opacity-50 transition flex items-center gap-2">
              {loading ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"/>Generating...</> : '⚡ Generate Ledger'}
            </button>
            {generated && (
              <button onClick={reset} className="px-5 py-2.5 border border-gray-200 rounded-xl text-sm hover:bg-gray-50 transition">
                ✕ Reset
              </button>
            )}
          </div>
        </div>

        {/* ── GENERATED REPORT ── */}
        {generated && (
          <>
            {/* Report header + export */}
            <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-5">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div>
                  <h2 className="text-lg font-extrabold text-gray-900">
                    {partyType === 'trader' ? '🤝 Trader' : '🏭 Company'} Ledger — <span className="text-orange-600">{partyName}</span>
                  </h2>
                  <p className="text-sm text-gray-500 mt-0.5">Period: {periodLabel}</p>
                  <div className="flex gap-4 mt-2 text-xs text-gray-500">
                    <span>📋 {txnCount} transaction{txnCount !== 1 ? 's' : ''}</span>
                    <span>💳 {payCount} payment{payCount !== 1 ? 's' : ''}</span>
                    <span>📝 {rows.length} total entries</span>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-3">
                  {/* Opening + Closing balance cards */}
                  <div className="flex gap-3">
                    {openingRow && openingBalInf && (
                      <div className="rounded-xl px-4 py-3 border bg-gray-50 border-gray-200 text-right">
                        <p className="text-xs text-gray-400 font-semibold uppercase tracking-wide">Opening Balance</p>
                        <p className={`text-base font-extrabold ${openingBalInf.color}`}>
                          {openingBalInf.text} <span className="text-xs">{openingBalInf.label}</span>
                        </p>
                      </div>
                    )}
                    <div className={`rounded-xl px-4 py-3 border text-right ${finalBal > 0.01 ? 'bg-red-50 border-red-200' : finalBal < -0.01 ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200'}`}>
                      <p className="text-xs text-gray-500 font-semibold uppercase tracking-wide">Closing Balance</p>
                      <p className={`text-xl font-extrabold ${finalBalInfo.color}`}>
                        {finalBalInfo.text} <span className="text-sm">{finalBalInfo.label}</span>
                      </p>
                      <p className="text-xs text-gray-400 mt-0.5">
                        {finalBal > 0.01 ? `${partyType === 'trader' ? 'Trader owes you' : 'You owe company'}` : finalBal < -0.01 ? 'Advance/credit balance' : 'Fully settled'}
                      </p>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={exportCSV}
                      className="px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-xl text-xs font-bold transition">📥 CSV</button>
                    <button onClick={exportPDF}
                      className="px-3 py-2 bg-red-600 hover:bg-red-700 text-white rounded-xl text-xs font-bold transition">📄 PDF</button>
                  </div>
                </div>
              </div>
            </div>

            {/* Table */}
            {rows.length === 0 ? (
              <div className="bg-white rounded-2xl border border-gray-100 shadow-sm py-16 text-center">
                <div className="text-4xl mb-3">📋</div>
                <p className="text-gray-500 font-medium">No entries found for selected filters</p>
              </div>
            ) : (
              <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 border-b border-gray-100">
                      <tr>
                        {['#','Date','Vehicle No','Birds','Weight (Kg)','Avg Wt','Rate/Kg','Total Amt',
                          partyType === 'trader' ? 'Credit' : 'Debit', 'Method','Txn ID','Balance',''].map(h => (
                          <th key={h} className="text-left text-xs font-semibold text-gray-500 uppercase px-3 py-3 whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-50">
                      {rows.map((r, i) => {
                        const bal    = fmtBal(r.closingBalance);
                        const isTxn  = r.rowType === 'txn';
                        const isPay  = r.rowType === 'payment';
                        const isOpen = r.rowType === 'opening';

                        // ── Opening Balance Row ──
                        if (isOpen) {
                          return (
                            <tr key={i} className="bg-gray-100 border-b-2 border-gray-300">
                              <td className="px-3 py-3 text-xs text-gray-400 font-bold">—</td>
                              <td className="px-3 py-3 text-xs text-gray-600 whitespace-nowrap font-bold">{fmtDate(r.date)}</td>
                              <td colSpan={9} className="px-3 py-3 text-xs font-bold text-gray-600 italic">
                                📌 {r.description}
                              </td>
                              <td className={`px-3 py-3 text-xs font-extrabold whitespace-nowrap ${bal.color}`}>
                                {bal.text}
                              </td>
                              <td className={`px-3 py-3 text-xs font-extrabold ${bal.color}`}>{bal.label}</td>
                            </tr>
                          );
                        }

                        return (
                          <tr key={i} className={`transition ${isTxn ? 'hover:bg-orange-50/40' : 'bg-green-50/30 hover:bg-green-50/60'}`}>
                            <td className="px-3 py-2.5 text-xs text-gray-400">{i + (hasOpening ? 0 : 1)}</td>
                            <td className="px-3 py-2.5 text-xs text-gray-600 whitespace-nowrap">{fmtDate(r.date)}</td>
                            <td className="px-3 py-2.5 text-xs font-mono text-gray-700">{isTxn ? (r.vehicleNumber || '—') : ''}</td>
                            <td className="px-3 py-2.5 text-xs text-gray-700">{isTxn ? fmtNum(r.numberOfBirds) : ''}</td>
                            <td className="px-3 py-2.5 text-xs text-gray-700">{isTxn ? fmtWt(r.totalWeight) : ''}</td>
                            <td className="px-3 py-2.5 text-xs text-gray-700">{isTxn ? fmtWt(r.avgWeight) : ''}</td>
                            <td className="px-3 py-2.5 text-xs text-gray-700">{isTxn && r.rate != null ? `₹${r.rate}` : ''}</td>
                            <td className={`px-3 py-2.5 text-xs font-bold whitespace-nowrap ${isTxn ? 'text-gray-900' : ''}`}>
                              {isTxn ? fmtAmt(r.totalAmount) : ''}
                            </td>
                            <td className={`px-3 py-2.5 text-xs font-bold whitespace-nowrap ${isPay ? 'text-green-700' : ''}`}>
                              {isPay ? fmtAmt(r.creditDebitAmt) : ''}
                            </td>
                            <td className="px-3 py-2.5 text-xs text-gray-500">{isPay ? (r.paymentMethod || '—') : ''}</td>
                            <td className="px-3 py-2.5 text-xs font-mono text-gray-500">{isPay ? (r.transactionId || '—') : ''}</td>
                            <td className={`px-3 py-2.5 text-xs font-extrabold whitespace-nowrap ${bal.color}`}>
                              {bal.text}
                            </td>
                            <td className={`px-3 py-2.5 text-xs font-bold ${bal.color}`}>{bal.label}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                    <tfoot className={`border-t-2 ${finalBal > 0.01 ? 'bg-red-50 border-red-200' : finalBal < -0.01 ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200'}`}>
                      <tr>
                        <td colSpan={11} className="px-3 py-3 text-xs font-extrabold text-gray-700 uppercase">
                          Final Closing Balance ({rows.length} entries)
                        </td>
                        <td className={`px-3 py-3 text-sm font-extrabold whitespace-nowrap ${finalBalInfo.color}`}>
                          {finalBalInfo.text}
                        </td>
                        <td className={`px-3 py-3 text-sm font-extrabold ${finalBalInfo.color}`}>{finalBalInfo.label}</td>
                      </tr>
                    </tfoot>
                  </table>
                </div>
              </div>
            )}

            {/* Legend */}
            <div className="bg-white rounded-xl border border-gray-100 px-4 py-3 flex flex-wrap items-center gap-4 text-xs">
              <span className="font-bold text-gray-500">Legend:</span>
              <span className="flex items-center gap-1.5"><span className="w-3 h-3 bg-gray-200 border border-gray-300 rounded inline-block"></span><span className="text-gray-600">Opening Balance</span></span>
              <span className="flex items-center gap-1.5"><span className="w-3 h-3 bg-orange-50 border border-orange-200 rounded inline-block"></span><span className="text-gray-600">Transaction row</span></span>
              <span className="flex items-center gap-1.5"><span className="w-3 h-3 bg-green-50 border border-green-200 rounded inline-block"></span><span className="text-gray-600">Payment row</span></span>
              <span className="text-red-600 font-semibold">DR = Amount owed</span>
              <span className="text-green-600 font-semibold">CR = Advance/credit balance</span>
              <span className="text-gray-500 font-semibold">NIL = Fully settled</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
