import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/db/prisma';
import { requireAuth } from '@/lib/auth/middleware';
import { syncBankStatement, removeBankStatement } from '@/lib/bank-statement-sync';

export async function PUT(req: NextRequest, { params }: { params: { id: string } }) {
  const { error } = await requireAuth(['admin', 'accountant']);
  if (error) return error;

  const body = await req.json();
  const { date, expenseType, amount, transactionId, bankAccount, paymentMethod, notes } = body;

  // Fetch before update so we know the createdBy for bank statement sync
  const before = await prisma.expense.findUnique({
    where:  { id: parseInt(params.id) },
    select: { createdBy: true, bankAccountId: true },
  });
  if (!before) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const expense = await prisma.expense.update({
    where: { id: parseInt(params.id) },
    data: {
      ...(date             !== undefined && { date: new Date(date) }),
      ...(expenseType      !== undefined && { expenseType }),
      ...(amount           !== undefined && { amount: parseFloat(amount) }),
      ...(transactionId    !== undefined && { transactionId: transactionId || '' }),
      ...(bankAccount      !== undefined && { bankAccountId: bankAccount ? parseInt(bankAccount) : null }),
      ...(paymentMethod                  && { paymentMethod: paymentMethod as any }),
      ...(notes            !== undefined && { notes }),
    },
  });

  // Sync bank statement:
  // • If updated expense still has a bank account → upsert entry (handles account change too)
  // • If bank account was removed → delete any existing entry
  if (expense.bankAccountId) {
    await syncBankStatement({
      bankAccountId: expense.bankAccountId,
      date:          expense.date,
      credit:        0,
      debit:         expense.amount,
      description:   `Expense: ${expense.expenseType}`,
      remark:        `${expense.expenseType} | ${expense.paymentMethod}`,
      transactionId: expense.transactionId || '',
      sourceType:    'expense',
      sourceId:      expense.id,
      createdBy:     before.createdBy,
    });
  } else {
    // Bank account removed — clean up any existing bank statement entry
    await removeBankStatement({ sourceType: 'expense', sourceId: expense.id });
  }

  return NextResponse.json({ expense: { ...expense, _id: String(expense.id) } });
}

export async function DELETE(_req: NextRequest, { params }: { params: { id: string } }) {
  const { error } = await requireAuth(['admin', 'accountant']);
  if (error) return error;

  const expenseId = parseInt(params.id);

  // Remove the bank statement entry and recalculate subsequent balances before deleting
  await removeBankStatement({ sourceType: 'expense', sourceId: expenseId });

  await prisma.expense.delete({ where: { id: expenseId } });
  return NextResponse.json({ message: 'Deleted' });
}
