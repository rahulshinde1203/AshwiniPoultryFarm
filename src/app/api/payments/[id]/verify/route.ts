import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/db/prisma';
import { requireAuth } from '@/lib/auth/middleware';
import { syncBankStatement } from '@/lib/bank-statement-sync';
import { notifyUser } from '@/lib/notifications';

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth(['accountant', 'admin']);
  if (error) return error;

  const body = await req.json();
  const { action, transactionId, bankAccount, paymentMethod, chequeNumber, utrNumber, notes, rejectionReason } = body;

  const payment = await prisma.payment.findUnique({ where: { id: parseInt(params.id) } });
  if (!payment) return NextResponse.json({ error: 'Not found' }, { status: 404 });
  if (payment.status !== 'pending') return NextResponse.json({ error: 'Already processed' }, { status: 400 });

  const userId = parseInt((session!.user as any).id);

  if (action === 'verify') {
    if (payment.paymentFor === 'company' && (!transactionId || !paymentMethod))
      return NextResponse.json({ error: 'Transaction ID and payment method required for company verification' }, { status: 400 });

    const updated = await prisma.payment.update({
      where: { id: payment.id },
      data: {
        status: 'verified', verifiedById: userId, verifiedAt: new Date(),
        ...(notes && { notes }),
        ...(payment.paymentFor === 'company' && {
          transactionId: transactionId || '',
          paymentMethod: paymentMethod as any,
          bankAccountId: bankAccount ? parseInt(bankAccount) : null,
          chequeNumber: chequeNumber || '',
          utrNumber: utrNumber || '',
        }),
      },
    });

    // ── TRADER PAYMENT — update outstanding ──────────────────────────────
    if (payment.paymentFor === 'trader' && payment.traderId) {
      let remaining = payment.amount;
      const allPurchases = await prisma.purchase.findMany({
        where: { traderId: payment.traderId, createdBy: payment.createdBy },
        orderBy: { date: 'asc' },
        select: { id: true, outstandingAmount: true },
      });
      for (const purchase of allPurchases) {
        if (remaining <= 0) break;
        const deduct = Math.min(remaining, purchase.outstandingAmount > 0 ? purchase.outstandingAmount : 0);
        if (deduct > 0) {
          await prisma.purchase.update({ where: { id: purchase.id }, data: { outstandingAmount: { decrement: deduct } } });
          remaining -= deduct;
        }
      }
      if (remaining > 0 && allPurchases.length > 0) {
        const latestPurchase = allPurchases[allPurchases.length - 1];
        await prisma.purchase.update({ where: { id: latestPurchase.id }, data: { outstandingAmount: { decrement: remaining } } });
      }
      await prisma.trader.update({ where: { id: payment.traderId }, data: { outstandingBalance: { decrement: payment.amount } } });
    }

    // ── COMPANY PAYMENT — update outstanding ─────────────────────────────
    if (payment.paymentFor === 'company' && payment.companyId) {
      await prisma.company.update({ where: { id: payment.companyId }, data: { outstandingBalance: { decrement: payment.amount } } });
    }

    // ── AUTO SYNC BANK STATEMENT ─────────────────────────────────────────
    // Use the final bankAccountId (updated for company, original for trader)
    const finalPayment = await prisma.payment.findUnique({ where: { id: payment.id } });
    if (finalPayment?.bankAccountId) {
      try {
        const txnId = finalPayment.utrNumber || finalPayment.chequeNumber || finalPayment.transactionId || '';
        if (finalPayment.paymentFor === 'trader') {
          const trader = await prisma.trader.findUnique({ where: { id: finalPayment.traderId! }, select: { name: true } });
          await syncBankStatement({
            bankAccountId: finalPayment.bankAccountId,
            date: finalPayment.date,
            credit: finalPayment.amount, debit: 0,
            description: 'Payment received from trader',
            remark: `Received from: ${trader?.name || 'Trader'}`,
            transactionId: txnId,
            sourceType: 'payment_trader',
            sourceId: finalPayment.id,
            createdBy: userId,
          });
        } else if (finalPayment.paymentFor === 'company') {
          const company = await prisma.company.findUnique({ where: { id: finalPayment.companyId! }, select: { name: true } });
          await syncBankStatement({
            bankAccountId: finalPayment.bankAccountId,
            date: finalPayment.date,
            credit: 0, debit: finalPayment.amount,
            description: 'Payment made to company',
            remark: `Paid to: ${company?.name || 'Company'}`,
            transactionId: txnId,
            sourceType: 'payment_company',
            sourceId: finalPayment.id,
            createdBy: userId,
          });
        }
      } catch (syncErr) {
        // Don't fail the verification if sync fails
        console.error('Bank statement sync error:', syncErr);
      }
    }

    // Notify the payment creator
    await notifyUser({
      userId: payment.createdBy,
      type: 'payment_verified',
      title: '✅ Payment Verified',
      body: `Your payment of ₹${payment.amount.toLocaleString('en-IN')} has been verified.`,
      link: '/dashboard/salesperson/payments',
    });

    return NextResponse.json({ payment: { ...updated, _id: String(updated.id) } });

  } else if (action === 'reject') {
    const updated = await prisma.payment.update({
      where: { id: payment.id },
      data: { status: 'rejected', rejectionReason: rejectionReason || '', verifiedById: userId, verifiedAt: new Date() },
    });

    await notifyUser({
      userId: payment.createdBy,
      type: 'payment_rejected',
      title: '❌ Payment Rejected',
      body: `Your payment request was rejected. ${rejectionReason || ''}`.trim(),
      link: '/dashboard/salesperson/payments',
    });

    return NextResponse.json({ payment: { ...updated, _id: String(updated.id) } });
  }

  return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
}