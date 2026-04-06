import 'server-only';

import { mkdir, writeFile } from 'fs/promises';
import path from 'path';
import { randomUUID } from 'crypto';

const MAX_UPLOAD_SIZE = 5 * 1024 * 1024;
const MIME_TO_EXT: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'application/pdf': 'pdf',
};

export const ALLOWED_UPLOAD_TYPES = Object.keys(MIME_TO_EXT);

function sanitizeFolderName(folder: string) {
  const cleaned = folder.toLowerCase().replace(/[^a-z0-9-_]/g, '');
  return cleaned || 'misc';
}

function getFileExtension(file: File) {
  const fromName = path.extname(file.name).replace('.', '').toLowerCase();
  if (fromName) return fromName;
  return MIME_TO_EXT[file.type] || 'bin';
}

export async function saveUploadedFile(file: File, folder = 'misc') {
  if (!ALLOWED_UPLOAD_TYPES.includes(file.type)) {
    throw new Error('Only JPG, PNG, and PDF files are allowed');
  }

  if (file.size > MAX_UPLOAD_SIZE) {
    throw new Error('File size must be under 5MB');
  }

  const safeFolder = sanitizeFolderName(folder);
  const ext = getFileExtension(file);
  const fileName = `${Date.now()}-${randomUUID()}.${ext}`;
  const relativePath = `/uploads/${safeFolder}/${fileName}`;
  const absolutePath = path.join(process.cwd(), 'public', 'uploads', safeFolder, fileName);

  await mkdir(path.dirname(absolutePath), { recursive: true });
  await writeFile(absolutePath, Buffer.from(await file.arrayBuffer()));

  return relativePath;
}
