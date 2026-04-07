import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/db/prisma';
import { requireAuth } from '@/lib/auth/middleware';
import * as XLSX from 'xlsx';

const dayEnd = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate(), 23, 59, 59, 999);

const TYPE_LABEL: Record<string, string> = {
  manual:          'Manual Entry',
  payment_trader:  'Trader Payment',
  payment_company: 'Company Payment',
  expense:         'Expense',
};

export async function GET(req: NextRequest) {
  const { error } = await requireAuth(['admin', 'accountant']);
  if (error) return error;

  const sp            = req.nextUrl.searchParams;
  const bankAccountId = sp.get('bankAccount') ? parseInt(sp.get('bankAccount')!) : null;
  if (!bankAccountId)
    return NextResponse.json({ error: 'bankAccount required' }, { status: 400 });

  const period = sp.get('period') || 'all';
  let dateWhere: any = {}; let filterStart: Date | null = null; let label = 'All-Time';

  if (period === 'month') {
    const m = parseInt(sp.get('month') || '0'), y = parseInt(sp.get('year') || '0');
    if (m && y) { filterStart = new Date(y, m - 1, 1); dateWhere = { gte: filterStart, lte: new Date(y, m, 0, 23, 59, 59, 999) }; label = filterStart.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' }); }
  } else if (period === 'day') {
    const d = sp.get('date') ? new Date(sp.get('date')!) : null;
    if (d) { filterStart = new Date(d.getFullYear(), d.getMonth(), d.getDate()); dateWhere = { gte: filterStart, lte: dayEnd(d) }; label = d.toLocaleDateString('en-IN'); }
  } else if (period === 'range') {
    const s = sp.get('start') ? new Date(sp.get('start')!) : null;
    const e = sp.get('end')   ? new Date(sp.get('end')!)   : null;
    if (s && e) { filterStart = new Date(s.getFullYear(), s.getMonth(), s.getDate()); dateWhere = { gte: filterStart, lte: dayEnd(e) }; label = `${sp.get('start')}-to-${sp.get('end')}`; }
  }

  try {
    const [statements, account] = await Promise.all([
      prisma.bankStatement.findMany({
        where: { bankAccountId, ...(Object.keys(dateWhere).length ? { date: dateWhere } : {}) },
        orderBy: [{ date: 'asc' }, { createdAt: 'asc' }],
        include: { bankAccount: { select: { bankName: true, accountNumber: true, accountHolderName: true } } },
      }),
      prisma.bankAccount.findUnique({ where: { id: bankAccountId }, select: { bankName: true, accountNumber: true, accountHolderName: true } }),
    ]);

    let openingBalance = 0;
    if (filterStart) {
      const prev = await prisma.bankStatement.findFirst({
        where: { bankAccountId, date: { lt: filterStart } },
        orderBy: [{ date: 'desc' }, { createdAt: 'desc' }],
        select: { balance: true },
      });
      openingBalance = prev?.balance ?? 0;
    }

    const totalCredit    = statements.reduce((s, x) => s + x.creditAmount, 0);
    const totalDebit     = statements.reduce((s, x) => s + x.debitAmount, 0);
    const closingBalance = statements.length > 0 ? (statements[statements.length - 1].balance ?? 0) : openingBalance;
    const f2 = (n: number) => +n.toFixed(2);
    const fDate = (d: Date) => new Date(d).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });

    const rows: any[] = [];

    // Bank info header
    rows.push({ '#': 'Bank Statement Report', Date: account?.bankName ?? '', Account: `A/C: ****${account?.accountNumber.slice(-4)}`, Description: account?.accountHolderName ?? '', Remark: '', 'Txn ID': '', Type: '', 'Credit (₹)': '', 'Debit (₹)': '', 'Balance (₹)': '' });
    rows.push({ '#': 'Period:', Date: label, Account: '', Description: '', Remark: '', 'Txn ID': '', Type: '', 'Credit (₹)': '', 'Debit (₹)': '', 'Balance (₹)': '' });
    rows.push({});

    if (filterStart) {
      rows.push({ '#': '—', Date: 'Opening Balance', Account: account?.bankName ?? '', Description: 'Balance brought forward', Remark: '', 'Txn ID': '', Type: '', 'Credit (₹)': '', 'Debit (₹)': '', 'Balance (₹)': f2(openingBalance) });
    }

    statements.forEach((s, i) => {
      rows.push({
        '#': i + 1,
        Date: fDate(s.date),
        Account: s.bankAccount?.bankName ?? '',
        Description: s.description ?? '',
        Remark: s.remark ?? '',
        'Txn ID': s.transactionId ?? '',
        Type: TYPE_LABEL[s.sourceType] ?? s.sourceType,
        'Credit (₹)': s.creditAmount > 0 ? f2(s.creditAmount) : '',
        'Debit (₹)':  s.debitAmount  > 0 ? f2(s.debitAmount)  : '',
        'Balance (₹)': f2(s.balance ?? 0),
      });
    });

    rows.push({});
    rows.push({ '#': '', Date: 'TOTAL', Account: `${statements.length} entries`, Description: '', Remark: '', 'Txn ID': '', Type: '', 'Credit (₹)': f2(totalCredit), 'Debit (₹)': f2(totalDebit), 'Balance (₹)': '' });
    rows.push({ '#': '—', Date: 'Closing Balance', Account: account?.bankName ?? '', Description: 'Final balance after last transaction', Remark: '', 'Txn ID': '', Type: '', 'Credit (₹)': '', 'Debit (₹)': '', 'Balance (₹)': f2(closingBalance) });

    const ws = XLSX.utils.json_to_sheet(rows);
    ws['!cols'] = [{ wch: 5 }, { wch: 14 }, { wch: 20 }, { wch: 38 }, { wch: 24 }, { wch: 18 }, { wch: 16 }, { wch: 14 }, { wch: 14 }, { wch: 16 }];
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Bank Statement');
    const buffer   = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    const filename = `bank-statement-${(account?.bankName ?? 'export').replace(/\s+/g, '-')}-${label.replace(/[^a-zA-Z0-9-]/g, '-')}.xlsx`;

    return new NextResponse(buffer, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Cache-Control': 'no-store',
      },
    });
  } catch (err: any) {
    console.error('Export error:', err.message);
    return NextResponse.json({ error: 'Export failed' }, { status: 500 });
  }
}
