'use client';
import { useState, useEffect, useCallback } from 'react';

type Salesperson = { id: number; name: string };
type Party       = { id: number; name: string };

type OpeningBalance = {
  id: number;
  salespersonId: number;
  salespersonName: string;
  partyType: 'trader' | 'company';
  partyId: number;
  partyName: string;
  amount: number;
  notes: string;
  updatedAt: string;
};

const fmt = (n: number) =>
  '₹' + Math.abs(n).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

export default function OpeningBalancesPage() {
  const [salespersons, setSalespersons] = useState<Salesperson[]>([]);
  const [traders,      setTraders]      = useState<Party[]>([]);
  const [companies,    setCompanies]    = useState<Party[]>([]);

  const [filterSP,     setFilterSP]     = useState('');
  const [records,      setRecords]       = useState<OpeningBalance[]>([]);
  const [loading,      setLoading]       = useState(false);

  // Form state
  const [showForm,     setShowForm]      = useState(false);
  const [editId,       setEditId]        = useState<number | null>(null);
  const [formSP,       setFormSP]        = useState('');
  const [formPartyType,setFormPartyType] = useState<'trader' | 'company'>('trader');
  const [formPartyId,  setFormPartyId]   = useState('');
  const [formAmount,   setFormAmount]    = useState('');
  const [formNotes,    setFormNotes]     = useState('');
  const [saving,       setSaving]        = useState(false);
  const [formErr,      setFormErr]       = useState('');

  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);
  const [toast,         setToast]         = useState('');

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(''), 3000);
  };

  // Load dropdowns on mount
  useEffect(() => {
    Promise.all([
      fetch('/api/users').then(r => r.json()),
      fetch('/api/traders').then(r => r.json()),
      fetch('/api/companies').then(r => r.json()),
    ]).then(([usersData, tradersData, companiesData]) => {
      setSalespersons(
        (usersData.users || [])
          .filter((u: any) => u.role === 'salesperson' && u.isActive)
          .map((u: any) => ({ id: u.id, name: u.name }))
      );
      setTraders((tradersData.traders || []).map((t: any) => ({ id: t.id, name: t.name })));
      setCompanies((companiesData.companies || []).map((c: any) => ({ id: c.id, name: c.name })));
    });
  }, []);

  const loadRecords = useCallback(async (spId: string) => {
    if (!spId) { setRecords([]); return; }
    setLoading(true);
    try {
      const res = await fetch(`/api/opening-balances?salespersonId=${spId}`);
      const data = await res.json();
      setRecords(data.openingBalances || []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadRecords(filterSP); }, [filterSP, loadRecords]);

  const openAdd = () => {
    setEditId(null);
    setFormSP(filterSP);
    setFormPartyType('trader');
    setFormPartyId('');
    setFormAmount('');
    setFormNotes('');
    setFormErr('');
    setShowForm(true);
  };

  const openEdit = (r: OpeningBalance) => {
    setEditId(r.id);
    setFormSP(String(r.salespersonId));
    setFormPartyType(r.partyType);
    setFormPartyId(String(r.partyId));
    setFormAmount(String(r.amount));
    setFormNotes(r.notes);
    setFormErr('');
    setShowForm(true);
  };

  const handleSave = async () => {
    if (!formSP || !formPartyId || formAmount === '') {
      setFormErr('Salesperson, party and amount are required.');
      return;
    }
    const amt = parseFloat(formAmount);
    if (isNaN(amt)) { setFormErr('Amount must be a valid number.'); return; }

    setSaving(true); setFormErr('');
    try {
      let res: Response;
      if (editId) {
        res = await fetch(`/api/opening-balances/${editId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ amount: amt, notes: formNotes }),
        });
      } else {
        res = await fetch('/api/opening-balances', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            salespersonId: parseInt(formSP),
            partyType:     formPartyType,
            partyId:       parseInt(formPartyId),
            amount:        amt,
            notes:         formNotes,
          }),
        });
      }
      const data = await res.json();
      if (!res.ok) { setFormErr(data.error || 'Save failed.'); return; }
      setShowForm(false);
      showToast(editId ? 'Opening balance updated.' : 'Opening balance saved.');
      await loadRecords(filterSP || formSP);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: number) => {
    const res = await fetch(`/api/opening-balances/${id}`, { method: 'DELETE' });
    if (res.ok) {
      setDeleteConfirm(null);
      showToast('Opening balance deleted.');
      await loadRecords(filterSP);
    }
  };

  const parties = formPartyType === 'trader' ? traders : companies;

  return (
    <div className="p-4 max-w-5xl mx-auto">
      {/* Toast */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-green-600 text-white px-4 py-2 rounded shadow-lg text-sm">
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-bold text-gray-800">Opening Balances</h1>
          <p className="text-sm text-gray-500">Pre-system balances per salesperson per party</p>
        </div>
        <button
          onClick={openAdd}
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded"
        >
          + Add Opening Balance
        </button>
      </div>

      {/* Add / Edit Form */}
      {showForm && (
        <div className="bg-white border border-gray-200 rounded-lg p-4 mb-4 shadow-sm">
          <h2 className="font-semibold text-gray-700 mb-3">{editId ? 'Edit' : 'Add'} Opening Balance</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Salesperson */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Salesperson *</label>
              <select
                value={formSP}
                onChange={e => setFormSP(e.target.value)}
                disabled={!!editId}
                className="w-full border border-gray-300 rounded px-2 py-1.5 text-sm disabled:bg-gray-100"
              >
                <option value="">Select salesperson</option>
                {salespersons.map(s => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>

            {/* Party Type */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Party Type *</label>
              <div className="flex gap-2 mt-1">
                {(['trader', 'company'] as const).map(pt => (
                  <button
                    key={pt}
                    disabled={!!editId}
                    onClick={() => { setFormPartyType(pt); setFormPartyId(''); }}
                    className={`flex-1 py-1.5 text-sm rounded border ${
                      formPartyType === pt
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-white text-gray-700 border-gray-300'
                    } ${editId ? 'opacity-60 cursor-not-allowed' : ''}`}
                  >
                    {pt.charAt(0).toUpperCase() + pt.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* Party */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                {formPartyType === 'trader' ? 'Trader' : 'Company'} *
              </label>
              <select
                value={formPartyId}
                onChange={e => setFormPartyId(e.target.value)}
                disabled={!!editId}
                className="w-full border border-gray-300 rounded px-2 py-1.5 text-sm disabled:bg-gray-100"
              >
                <option value="">Select {formPartyType}</option>
                {parties.map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            {/* Amount */}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                Amount (₹) * <span className="text-gray-400 font-normal">— positive = party owes salesperson</span>
              </label>
              <input
                type="number"
                step="0.01"
                value={formAmount}
                onChange={e => setFormAmount(e.target.value)}
                placeholder="e.g. 50000 or -10000"
                className="w-full border border-gray-300 rounded px-2 py-1.5 text-sm"
              />
            </div>

            {/* Notes */}
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-gray-600 mb-1">Notes (optional)</label>
              <textarea
                value={formNotes}
                onChange={e => setFormNotes(e.target.value)}
                rows={2}
                placeholder="e.g. Balance carried forward from old register"
                className="w-full border border-gray-300 rounded px-2 py-1.5 text-sm"
              />
            </div>
          </div>

          {formErr && <p className="text-red-600 text-xs mt-2">{formErr}</p>}

          <div className="flex gap-2 mt-3">
            <button
              onClick={handleSave}
              disabled={saving}
              className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-1.5 rounded disabled:opacity-60"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm px-4 py-1.5 rounded"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Filter by salesperson */}
      <div className="bg-white border border-gray-200 rounded-lg p-3 mb-4 flex items-center gap-3">
        <label className="text-sm text-gray-600 whitespace-nowrap">Filter by Salesperson:</label>
        <select
          value={filterSP}
          onChange={e => setFilterSP(e.target.value)}
          className="border border-gray-300 rounded px-2 py-1.5 text-sm flex-1 max-w-xs"
        >
          <option value="">— Select salesperson —</option>
          {salespersons.map(s => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>
        {filterSP && (
          <button onClick={() => setFilterSP('')} className="text-xs text-gray-400 hover:text-gray-600">
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      {!filterSP ? (
        <div className="text-center text-gray-400 py-16 text-sm">Select a salesperson to view their opening balances.</div>
      ) : loading ? (
        <div className="text-center text-gray-400 py-16 text-sm">Loading...</div>
      ) : records.length === 0 ? (
        <div className="text-center text-gray-400 py-16 text-sm">No opening balances set for this salesperson.</div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-2 text-gray-600 font-medium">Party Type</th>
                <th className="text-left px-4 py-2 text-gray-600 font-medium">Party Name</th>
                <th className="text-right px-4 py-2 text-gray-600 font-medium">Amount</th>
                <th className="text-left px-4 py-2 text-gray-600 font-medium">Notes</th>
                <th className="text-right px-4 py-2 text-gray-600 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {records.map(r => (
                <tr key={r.id} className="hover:bg-gray-50">
                  <td className="px-4 py-2">
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                      r.partyType === 'trader'
                        ? 'bg-blue-100 text-blue-700'
                        : 'bg-purple-100 text-purple-700'
                    }`}>
                      {r.partyType.charAt(0).toUpperCase() + r.partyType.slice(1)}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-medium text-gray-800">{r.partyName}</td>
                  <td className={`px-4 py-2 text-right font-semibold ${
                    r.amount > 0 ? 'text-red-600' : r.amount < 0 ? 'text-green-600' : 'text-gray-400'
                  }`}>
                    {r.amount === 0
                      ? '₹0.00'
                      : `${r.amount > 0 ? '+' : '−'}${fmt(r.amount)}`}
                    {r.amount !== 0 && (
                      <div className="text-xs font-normal text-gray-400">
                        {r.amount > 0 ? 'DR (party owes SP)' : 'CR (SP owes party)'}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2 text-gray-500 text-xs max-w-xs truncate">{r.notes || '—'}</td>
                  <td className="px-4 py-2 text-right">
                    {deleteConfirm === r.id ? (
                      <span className="inline-flex items-center gap-1">
                        <span className="text-xs text-gray-500">Delete?</span>
                        <button
                          onClick={() => handleDelete(r.id)}
                          className="text-xs text-red-600 hover:underline"
                        >Yes</button>
                        <button
                          onClick={() => setDeleteConfirm(null)}
                          className="text-xs text-gray-500 hover:underline"
                        >No</button>
                      </span>
                    ) : (
                      <span className="inline-flex gap-2">
                        <button
                          onClick={() => openEdit(r)}
                          className="text-xs text-blue-600 hover:underline"
                        >Edit</button>
                        <button
                          onClick={() => setDeleteConfirm(r.id)}
                          className="text-xs text-red-500 hover:underline"
                        >Delete</button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
