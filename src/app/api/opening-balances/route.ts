import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/db/prisma';
import { requireAuth } from '@/lib/auth/middleware';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const db = prisma as any;

// GET /api/opening-balances?salespersonId=X
export async function GET(req: NextRequest) {
  const { error, session } = await requireAuth(['admin', 'accountant', 'salesperson']);
  if (error) return error;

  try {
    const userId = parseInt((session!.user as any).id);
    const role   = (session!.user as any).role as string;
    const isSP   = role === 'salesperson';

    const sp            = req.nextUrl.searchParams;
    const salespersonId = sp.get('salespersonId') ? parseInt(sp.get('salespersonId')!) : null;

    const queryId = isSP ? userId : (salespersonId ?? undefined);
    if (!queryId) return NextResponse.json({ openingBalances: [] });
    if (isSP && queryId !== userId) return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

    const records = await db.salespersonOpeningBalance.findMany({
      where: { salespersonId: queryId },
      include: { salesperson: { select: { id: true, name: true } } },
      orderBy: [{ partyType: 'asc' }, { partyId: 'asc' }],
    });

    const traderIds  = records.filter((r: any) => r.partyType === 'trader').map((r: any) => r.partyId);
    const companyIds = records.filter((r: any) => r.partyType === 'company').map((r: any) => r.partyId);

    const [traders, companies] = await Promise.all([
      traderIds.length  ? prisma.trader.findMany({ where: { id: { in: traderIds } },  select: { id: true, name: true } }) : [],
      companyIds.length ? prisma.company.findMany({ where: { id: { in: companyIds } }, select: { id: true, name: true } }) : [],
    ]);

    const traderNameMap  = Object.fromEntries((traders  as any[]).map(t => [t.id, t.name]));
    const companyNameMap = Object.fromEntries((companies as any[]).map(c => [c.id, c.name]));

    const openingBalances = records.map((r: any) => ({
      id:              r.id,
      salespersonId:   r.salespersonId,
      salespersonName: r.salesperson.name,
      partyType:       r.partyType,
      partyId:         r.partyId,
      partyName:       r.partyType === 'trader' ? (traderNameMap[r.partyId] || '') : (companyNameMap[r.partyId] || ''),
      amount:          r.amount,
      date:            r.date ? r.date.toISOString().split('T')[0] : null,
      notes:           r.notes,
      createdAt:       r.createdAt.toISOString(),
      updatedAt:       r.updatedAt.toISOString(),
    }));

    return NextResponse.json({ openingBalances });
  } catch (err: any) {
    console.error('GET /api/opening-balances:', err.message);
    return NextResponse.json({ error: err.message || 'Failed to load opening balances' }, { status: 500 });
  }
}

// POST /api/opening-balances — upsert; admin/accountant only
export async function POST(req: NextRequest) {
  const { error, session } = await requireAuth(['admin', 'accountant']);
  if (error) return error;

  try {
    const userId = parseInt((session!.user as any).id);
    const body   = await req.json();
    const { salespersonId, partyType, partyId, amount, notes, date } = body;

    if (!salespersonId || !partyType || !partyId || amount === undefined || amount === null) {
      return NextResponse.json({ error: 'salespersonId, partyType, partyId and amount are required' }, { status: 400 });
    }
    if (!['trader', 'company'].includes(partyType)) {
      return NextResponse.json({ error: 'partyType must be trader or company' }, { status: 400 });
    }
    if (isNaN(parseFloat(amount))) {
      return NextResponse.json({ error: 'amount must be a number' }, { status: 400 });
    }

    const parsedDate = date ? new Date(date) : null;

    const record = await db.salespersonOpeningBalance.upsert({
      where: {
        salespersonId_partyType_partyId: {
          salespersonId: parseInt(salespersonId),
          partyType: partyType as any,
          partyId:   parseInt(partyId),
        },
      },
      create: {
        salespersonId: parseInt(salespersonId),
        partyType: partyType as any,
        partyId:   parseInt(partyId),
        amount:    parseFloat(amount),
        date:      parsedDate,
        notes:     notes || '',
        createdBy: userId,
      },
      update: {
        amount: parseFloat(amount),
        date:   parsedDate,
        notes:  notes ?? '',
      },
    });

    return NextResponse.json({ openingBalance: record });
  } catch (err: any) {
    console.error('POST /api/opening-balances:', err.message);
    return NextResponse.json({ error: err.message || 'Failed to save opening balance' }, { status: 500 });
  }
}
