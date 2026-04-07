'use client';
import { useEffect, useState } from 'react';
import { useSession } from 'next-auth/react';
import { toast } from 'sonner';

const fmt = (n: number) =>
  `₹${(n || 0).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;

const EMPTY_FORM = {
  bankName: '', accountHolderName: '', accountNumber: '',
  ifscCode: '', branchName: '', upiId: '', currentBalance: '',
};

export default function BankAccountsPage() {
  const { data: session } = useSession();
  const role = (session?.user as any)?.role as string;
  const isAdmin = role === 'admin';

  const [accounts, setAccounts]     = useState<any[]>([]);
  const [loading,  setLoading]      = useState(true);
  const [showAdd,  setShowAdd]      = useState(false);
  const [editAcc,  setEditAcc]      = useState<any>(null);
  const [saving,   setSaving]       = useState(false);
  const [form,     setForm]         = useState(EMPTY_FORM);

  const load = () => {
    setLoading(true);
    fetch('/api/bank-accounts?includeInactive=true')
      .then(r => r.json())
      .then(d => setAccounts(d.accounts || []))
      .catch(() => toast.error('Failed to load accounts'))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const openAdd = () => { setForm(EMPTY_FORM); setShowAdd(true); };

  const openEdit = (a: any) => {
    setForm({
      bankName:          a.bankName,
      accountHolderName: a.accountHolderName,
      accountNumber:     a.accountNumber,
      ifscCode:          a.ifscCode,
      branchName:        a.branchName,
      upiId:             a.upiId || '',
      currentBalance:    String(a.currentBalance ?? ''),
    });
    setEditAcc(a);
  };

  const closeModals = () => { setShowAdd(false); setEditAcc(null); };

  const handleSave = async () => {
    if (!form.bankName.trim() || !form.accountHolderName.trim() ||
        !form.accountNumber.trim() || !form.ifscCode.trim() || !form.branchName.trim()) {
      toast.error('Fill all required fields');
      return;
    }
    setSaving(true);
    try {
      const payload = { ...form, ifscCode: form.ifscCode.toUpperCase() };
      const isEdit  = !!editAcc;
      const res = await fetch(
        isEdit ? `/api/bank-accounts/${editAcc._id}` : '/api/bank-accounts',
        { method: isEdit ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) },
      );
      const data = await res.json();
      if (!res.ok) { toast.error(data.error || 'Failed'); return; }
      toast.success(isEdit ? 'Account updated' : 'Account added');
      closeModals();
      load();
    } catch { toast.error('Network error'); }
    finally { setSaving(false); }
  };

  const toggleActive = async (a: any) => {
    if (!confirm(`${a.isActive ? 'Deactivate' : 'Activate'} "${a.bankName}"?`)) return;
    const res = a.isActive
      ? await fetch(`/api/bank-accounts/${a._id}`, { method: 'DELETE' })
      : await fetch(`/api/bank-accounts/${a._id}`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ isActive: true }),
        });
    if (res.ok) { toast.success(a.isActive ? 'Deactivated' : 'Activated'); load(); }
    else toast.error('Failed');
  };

  const modalForm = (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6">
        <h2 className="text-lg font-bold text-gray-800 mb-4">
          {editAcc ? 'Edit Bank Account' : 'Add Bank Account'}
        </h2>
        <div className="space-y-3">
          {[
            { label: 'Bank Name *',            key: 'bankName',          placeholder: 'e.g. State Bank of India' },
            { label: 'Account Holder Name *',  key: 'accountHolderName', placeholder: 'Name on account' },
            { label: 'Account Number *',       key: 'accountNumber',     placeholder: '000123456789' },
            { label: 'IFSC Code *',            key: 'ifscCode',          placeholder: 'SBIN0001234' },
            { label: 'Branch Name *',          key: 'branchName',        placeholder: 'Main Branch' },
            { label: 'UPI ID',                 key: 'upiId',             placeholder: 'optional' },
            { label: 'Opening Balance (₹)',    key: 'currentBalance',    placeholder: '0.00' },
          ].map(({ label, key, placeholder }) => (
            <div key={key}>
              <label className="block text-xs font-semibold text-gray-500 mb-1">{label}</label>
              <input
                className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-400"
                placeholder={placeholder}
                value={(form as any)[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
              />
            </div>
          ))}
        </div>
        <div className="flex gap-3 mt-5">
          <button onClick={closeModals}
            className="flex-1 py-2 border border-gray-200 rounded-xl text-sm font-semibold text-gray-600 hover:bg-gray-50">
            Cancel
          </button>
          <button onClick={handleSave} disabled={saving}
            className="flex-1 py-2 bg-orange-500 text-white rounded-xl text-sm font-bold hover:bg-orange-600 disabled:opacity-50">
            {saving ? 'Saving…' : editAcc ? 'Update' : 'Add Account'}
          </button>
        </div>
      </div>
    </div>
  );

  const active   = accounts.filter(a => a.isActive);
  const inactive = accounts.filter(a => !a.isActive);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-700 to-gray-800 px-5 sm:px-8 py-6">
        <div className="max-w-4xl mx-auto flex items-center justify-between gap-3">
          <div>
            <h1 className="text-white font-extrabold text-xl sm:text-2xl">Bank Accounts</h1>
            <p className="text-slate-300 text-sm mt-0.5">{active.length} active account{active.length !== 1 ? 's' : ''}</p>
          </div>
          {isAdmin && (
            <button onClick={openAdd}
              className="px-4 py-2 bg-orange-500 text-white rounded-xl text-sm font-bold hover:bg-orange-600 transition">
              + Add Account
            </button>
          )}
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-4 sm:px-8 py-6 space-y-4">
        {loading ? (
          <div className="py-20 text-center text-gray-400">Loading…</div>
        ) : accounts.length === 0 ? (
          <div className="py-20 text-center text-gray-400">
            <div className="text-4xl mb-3">🏦</div>
            <p className="font-semibold">No bank accounts yet</p>
            {isAdmin && <p className="text-sm mt-1">Click "Add Account" to get started</p>}
          </div>
        ) : (
          <>
            {/* Active accounts */}
            <div className="space-y-3">
              {active.map(a => (
                <div key={a._id}
                  className="bg-white rounded-2xl border border-gray-100 shadow-sm p-4 flex items-center gap-4">
                  <div className="w-11 h-11 rounded-xl bg-orange-50 flex items-center justify-center shrink-0">
                    <span className="text-xl">🏦</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-bold text-gray-900 truncate">{a.bankName}</p>
                    <p className="text-xs text-gray-500 mt-0.5">{a.accountHolderName}</p>
                    <p className="text-xs font-mono text-gray-400 mt-0.5">
                      ****{a.accountNumber?.slice(-4)} · {a.ifscCode} · {a.branchName}
                    </p>
                    {a.upiId && <p className="text-xs text-indigo-600 mt-0.5">UPI: {a.upiId}</p>}
                  </div>
                  <div className="text-right shrink-0">
                    <p className="font-extrabold text-blue-700 text-base">{fmt(a.currentBalance ?? 0)}</p>
                    <p className="text-xs text-gray-400 mt-0.5">Current Balance</p>
                    {isAdmin && (
                      <div className="flex gap-2 justify-end mt-2">
                        <button onClick={() => openEdit(a)}
                          className="px-3 py-1 text-xs font-semibold border border-gray-200 rounded-lg hover:bg-gray-50 text-gray-600">
                          Edit
                        </button>
                        <button onClick={() => toggleActive(a)}
                          className="px-3 py-1 text-xs font-semibold border border-red-200 rounded-lg hover:bg-red-50 text-red-600">
                          Deactivate
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Inactive accounts */}
            {inactive.length > 0 && (
              <div className="mt-6">
                <p className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-3">Inactive Accounts</p>
                <div className="space-y-2">
                  {inactive.map(a => (
                    <div key={a._id}
                      className="bg-white rounded-xl border border-dashed border-gray-200 p-4 flex items-center gap-4 opacity-60">
                      <div className="flex-1 min-w-0">
                        <p className="font-semibold text-gray-500 truncate">{a.bankName}</p>
                        <p className="text-xs text-gray-400">****{a.accountNumber?.slice(-4)} · {a.branchName}</p>
                      </div>
                      {isAdmin && (
                        <button onClick={() => toggleActive(a)}
                          className="px-3 py-1 text-xs font-semibold border border-green-200 rounded-lg hover:bg-green-50 text-green-700">
                          Activate
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {(showAdd || editAcc) && modalForm}
    </div>
  );
}
