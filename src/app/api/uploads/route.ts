import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth/middleware';
import { saveUploadedFile } from '@/lib/server/upload-storage';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const { error } = await requireAuth(['admin']);
  if (error) return error;

  const formData = await req.formData();
  const file = formData.get('file');
  const folder = String(formData.get('folder') || 'misc');

  if (!(file instanceof File)) {
    return NextResponse.json({ error: 'File is required' }, { status: 400 });
  }

  try {
    const savedPath = await saveUploadedFile(file, folder);
    return NextResponse.json({ path: savedPath });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Upload failed';
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
