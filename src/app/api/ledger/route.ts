import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/db/prisma';
import { requireAuth } from '@/lib/auth/middleware';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const db = prisma as any;

function dayBounds(d: string) {
  const dt = new Date(d);
  return {
    gte: new Date(dt.getFullYear(), dt.getMonth(), dt.getDate(), 0, 0, 0, 0),
    lte: new Date(dt.getFullYear(), dt.getMonth(), dt.getDate(), 23, 59, 59, 999),
  };
}

function buildDate(sp: URLSearchParams) {
  const period = sp.get('period') || 'all';
  const date   = sp.get('date')  || '';
  const month  = parseInt(sp.get('month') || '0');
  const year   = parseInt(sp.get('year')  || '0');
  const start  = sp.get('start') || '';
  const end    = sp.get('end')   || '';
  if (period === 'day'   && date)           return dayBounds(date);
  if (period === 'month' && month && year)  return { gte: new Date(year, month - 1, 1), lte: new Date(year, month, 0, 23, 59, 59, 999) };
  if (period === 'range' && start && end)   return { gte: dayBounds(start).gte, lte: dayBounds(end).lte };
  return undefined;
}

function getStartDate(sp: URLSearchParams): Date | null {
  const period = sp.get('period') || 'all';
  const date   = sp.get('date')  || '';
  const month  = parseInt(sp.get('month') || '0');
  const year   = parseInt(sp.get('year')  || '0');
  const start  = sp.get('start') || '';
  if (period === 'day'   && date)          return dayBounds(date).gte;
  if (period === 'month' && month && year) return new Date(year, month - 1, 1);
  if (period === 'range' && start)         return dayBounds(start).gte;
  return null; // 'all' = no opening balance row
}

export async function GET(req: NextRequest) {
  const { error, session } = await requireAuth(['admin', 'accountant', 'salesperson']);
  if (error) return error;

  const role   = (session!.user as any).role as string;
  const userId = parseInt((session!.user as any).id);
  const isSP   = role === 'salesperson';

  const sp        = req.nextUrl.searchParams;
  const partyType = sp.get('partyType') || 'trader';
  const partyId   = sp.get('partyId') ? parseInt(sp.get('partyId')!) : null;
  const dateWhere = buildDate(sp);
  const startDate = getStartDate(sp);

  try {
  if (!partyId) {
    const [traders, companies] = await Promise.all([
      isSP
        ? prisma.trader.findMany({ where: { isActive: true, purchases: { some: { createdBy: userId } } }, select: { id: true, name: true }, orderBy: { name: 'asc' } })
        : prisma.trader.findMany({ where: { isActive: true }, select: { id: true, name: true }, orderBy: { name: 'asc' } }),
      isSP
        ? prisma.company.findMany({ where: { isActive: true, purchases: { some: { createdBy: userId } } }, select: { id: true, name: true }, orderBy: { name: 'asc' } })
        : prisma.company.findMany({ where: { isActive: true }, select: { id: true, name: true }, orderBy: { name: 'asc' } }),
    ]);
    return NextResponse.json({
      rows: [], partyName: '', partyType, finalBalance: 0, openingBalance: null,
      traders:   traders.map((t: any) => ({ _id: String(t.id), name: t.name })),
      companies: companies.map((c: any) => ({ _id: String(c.id), name: c.name })),
      role,
    });
  }

  // ── 1. Opening Balance ───────────────────────────────────────────────────
  // Use `lt: startDate` (strictly before period start) — no 1ms edge case.
  let openingBalanceRow: any = null;

  // Fetch stored pre-system opening balance(s) for this party
  let storedBal = 0;
  if (partyId) {
    if (isSP) {
      // Salesperson: only their own opening balance for this party
      const ob = await db.salespersonOpeningBalance.findUnique({
        where: {
          salespersonId_partyType_partyId: {
            salespersonId: userId,
            partyType:     partyType as any,
            partyId:       partyId,
          },
        },
        select: { amount: true },
      });
      storedBal = ob?.amount ?? 0;
    } else {
      // Admin / accountant: sum all salespersons' opening balances for this party
      const obs = await db.salespersonOpeningBalance.findMany({
        where: { partyType: partyType as any, partyId: partyId },
        select: { amount: true },
      });
      storedBal = obs.reduce((sum: number, ob: any) => sum + (ob.amount ?? 0), 0);
    }
  }

  if (startDate) {
    const prevPurchaseWhere: any = { date: { lt: startDate } };
    const prevPaymentWhere:  any = { date: { lt: startDate }, status: 'verified' };

    if (isSP) { prevPurchaseWhere.createdBy = userId; prevPaymentWhere.createdBy = userId; }
    if (partyType === 'trader') {
      prevPurchaseWhere.traderId  = partyId;
      prevPaymentWhere.paymentFor = 'trader';
      prevPaymentWhere.traderId   = partyId;
    } else {
      prevPurchaseWhere.companyId = partyId;
      prevPaymentWhere.paymentFor = 'company';
      prevPaymentWhere.companyId  = partyId;
    }

    const [prevPurchases, prevPayments] = await Promise.all([
      prisma.purchase.aggregate({ where: prevPurchaseWhere, _sum: { saleTotalAmount: true, purchaseTotalAmount: true } }),
      prisma.payment.aggregate({ where: prevPaymentWhere, _sum: { amount: true } }),
    ]);

    const prevInvoice = partyType === 'trader'
      ? (prevPurchases._sum.saleTotalAmount     ?? 0)
      : (prevPurchases._sum.purchaseTotalAmount ?? 0);
    const prevPaid    = prevPayments._sum.amount ?? 0;
    const txnOpeningBal = +(prevInvoice - prevPaid).toFixed(2);
    const totalOpeningBal = +(txnOpeningBal + storedBal).toFixed(2);

    // Label: "before April 2026" / "before 07 Apr 2026" etc.
    const beforeLabel = startDate.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
    openingBalanceRow = {
      rowType:        'opening',
      date:           new Date(startDate.getTime() - 1).toISOString(), // 1 ms before period — for display only
      description:    `Opening Balance (before ${beforeLabel})`,
      closingBalance: totalOpeningBal,
      balanceDelta:   0,
      vehicleNumber:  '',
      numberOfBirds:  null,
      totalWeight:    null,
      avgWeight:      null,
      rate:           null,
      totalAmount:    null,
      creditDebitAmt: null,
      paymentMethod:  '',
      transactionId:  '',
    };
  } else if (storedBal !== 0) {
    // period = 'all' but there's a stored pre-system balance — show it as first row
    openingBalanceRow = {
      rowType:        'opening',
      date:           new Date(0).toISOString(), // epoch — always sorts first
      description:    'Opening Balance (pre-system)',
      closingBalance: storedBal,
      balanceDelta:   0,
      vehicleNumber:  '',
      numberOfBirds:  null,
      totalWeight:    null,
      avgWeight:      null,
      rate:           null,
      totalAmount:    null,
      creditDebitAmt: null,
      paymentMethod:  '',
      transactionId:  '',
    };
  }

  // ── 2. Fetch purchases ───────────────────────────────────────────────────
  const purchaseWhere: any = {};
  if (dateWhere) purchaseWhere.date = dateWhere;
  if (isSP) purchaseWhere.createdBy = userId;
  if (partyType === 'trader')  purchaseWhere.traderId  = partyId;
  if (partyType === 'company') purchaseWhere.companyId = partyId;

  const purchases = await prisma.purchase.findMany({
    where: purchaseWhere,
    orderBy: [{ date: 'asc' }, { createdAt: 'asc' }],
    include: { creator: { select: { name: true } } },
  });

  // ── 3. Fetch verified payments ───────────────────────────────────────────
  const paymentWhere: any = { status: 'verified' };
  if (dateWhere) paymentWhere.date = dateWhere;
  if (isSP) paymentWhere.createdBy = userId;
  if (partyType === 'trader')  { paymentWhere.paymentFor = 'trader';  paymentWhere.traderId  = partyId; }
  if (partyType === 'company') { paymentWhere.paymentFor = 'company'; paymentWhere.companyId = partyId; }

  const payments = await prisma.payment.findMany({
    where: paymentWhere,
    orderBy: [{ date: 'asc' }, { verifiedAt: 'asc' }],
  });

  // ── 4. Build ledger rows ─────────────────────────────────────────────────
  type LedgerRow = {
    rowType:       'txn' | 'payment' | 'opening';
    date:          string;
    sortKey:       number;
    description?:  string;
    vehicleNumber:   string;
    numberOfBirds:   number | null;
    totalWeight:     number | null;
    avgWeight:       number | null;
    rate:            number | null;
    totalAmount:     number | null;
    creditDebitAmt:  number | null;
    paymentMethod:   string;
    transactionId:   string;
    balanceDelta:    number;
    closingBalance:  number;
  };

  const rows: LedgerRow[] = [];

  for (const p of purchases) {
    const amount = partyType === 'trader'
      ? (p.saleTotalAmount || 0)
      : (p.purchaseTotalAmount || 0);
    const rate = partyType === 'trader'
      ? (p.saleRatePerKg || 0)
      : (p.purchaseRatePerKg || 0);

    rows.push({
      rowType: 'txn',
      date: p.date.toISOString(),
      sortKey: p.date.getTime() * 1000 + p.createdAt.getTime() % 1000,
      vehicleNumber: p.vehicleNumber || '',
      numberOfBirds: p.numberOfBirds,
      totalWeight:   +p.totalWeight.toFixed(3),
      avgWeight:     p.numberOfBirds > 0 ? +(p.totalWeight / p.numberOfBirds).toFixed(3) : 0,
      rate,
      totalAmount:   +amount.toFixed(2),
      creditDebitAmt: null,
      paymentMethod:  '',
      transactionId:  '',
      balanceDelta: +amount.toFixed(2),
      closingBalance: 0,
    });
  }

  for (const p of payments) {
    const txnId = p.utrNumber || p.chequeNumber || p.transactionId || '';
    rows.push({
      rowType: 'payment',
      date: p.date.toISOString(),
      sortKey: p.date.getTime() * 1000 + (p.verifiedAt?.getTime() || p.createdAt.getTime()) % 1000,
      vehicleNumber: '',
      numberOfBirds: null,
      totalWeight:   null,
      avgWeight:     null,
      rate:          null,
      totalAmount:   null,
      creditDebitAmt: +(p.amount || 0).toFixed(2),
      paymentMethod:  (p as any).paymentMethod || '',
      transactionId:  txnId,
      balanceDelta: -+(p.amount || 0).toFixed(2),
      closingBalance: 0,
    });
  }

  // ── 5. Sort + running balance ────────────────────────────────────────────
  rows.sort((a, b) => a.sortKey - b.sortKey);

  // Start running balance from opening balance if filter is applied
  let balance = openingBalanceRow ? openingBalanceRow.closingBalance : 0;
  for (const row of rows) {
    balance += row.balanceDelta;
    row.closingBalance = +balance.toFixed(2);
  }

  // ── 6. Party name ────────────────────────────────────────────────────────
  let partyName = '';
  if (partyType === 'trader') {
    const t = await prisma.trader.findUnique({ where: { id: partyId }, select: { name: true } });
    partyName = t?.name || '';
  } else {
    const c = await prisma.company.findUnique({ where: { id: partyId }, select: { name: true } });
    partyName = c?.name || '';
  }

  // ── 7. Dropdown lists ────────────────────────────────────────────────────
  const [traders, companies] = await Promise.all([
    isSP
      ? prisma.trader.findMany({ where: { isActive: true, purchases: { some: { createdBy: userId } } }, select: { id: true, name: true }, orderBy: { name: 'asc' } })
      : prisma.trader.findMany({ where: { isActive: true }, select: { id: true, name: true }, orderBy: { name: 'asc' } }),
    isSP
      ? prisma.company.findMany({ where: { isActive: true, purchases: { some: { createdBy: userId } } }, select: { id: true, name: true }, orderBy: { name: 'asc' } })
      : prisma.company.findMany({ where: { isActive: true }, select: { id: true, name: true }, orderBy: { name: 'asc' } }),
  ]);

  // Prepend opening balance row to the final rows array
  const allRows = openingBalanceRow ? [openingBalanceRow, ...rows] : rows;

  return NextResponse.json({
    rows: allRows,
    partyName,
    partyType,
    finalBalance: rows.length > 0 ? rows[rows.length - 1].closingBalance : (openingBalanceRow?.closingBalance ?? 0),
    openingBalance: openingBalanceRow,
    traders:   traders.map((t: any) => ({ _id: String(t.id), name: t.name })),
    companies: companies.map((c: any) => ({ _id: String(c.id), name: c.name })),
    role,
  });

  } catch (err: any) {
    console.error('GET /api/ledger:', err.message);
    return NextResponse.json({ error: err.message || 'Failed to load ledger' }, { status: 500 });
  }
}