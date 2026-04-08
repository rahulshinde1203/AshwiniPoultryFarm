import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/db/prisma';
import { requireAuth } from '@/lib/auth/middleware';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const db = prisma as any;

// PUT /api/opening-balances/[id] — admin/accountant only
export async function PUT(req: NextRequest, { params }: { params: { id: string } }) {
  const { error } = await requireAuth(['admin', 'accountant']);
  if (error) return error;

  try {
    const id   = parseInt(params.id);
    const body = await req.json();
    const { amount, notes, date } = body;

    if (amount === undefined || amount === null || isNaN(parseFloat(amount))) {
      return NextResponse.json({ error: 'amount is required and must be a number' }, { status: 400 });
    }

    const existing = await db.salespersonOpeningBalance.findUnique({ where: { id } });
    if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 });

    const updated = await db.salespersonOpeningBalance.update({
      where: { id },
      data: {
        amount: parseFloat(amount),
        date:   date !== undefined ? (date ? new Date(date) : null) : existing.date,
        notes:  notes ?? existing.notes,
      },
    });

    return NextResponse.json({ openingBalance: updated });
  } catch (err: any) {
    console.error('PUT /api/opening-balances/[id]:', err.message);
    return NextResponse.json({ error: err.message || 'Failed to update' }, { status: 500 });
  }
}

// DELETE /api/opening-balances/[id] — admin only
export async function DELETE(_req: NextRequest, { params }: { params: { id: string } }) {
  const { error } = await requireAuth(['admin']);
  if (error) return error;

  try {
    const id = parseInt(params.id);
    const existing = await db.salespersonOpeningBalance.findUnique({ where: { id } });
    if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 });

    await db.salespersonOpeningBalance.delete({ where: { id } });
    return NextResponse.json({ success: true });
  } catch (err: any) {
    console.error('DELETE /api/opening-balances/[id]:', err.message);
    return NextResponse.json({ error: err.message || 'Failed to delete' }, { status: 500 });
  }
}
