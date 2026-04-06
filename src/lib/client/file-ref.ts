const IMAGE_EXT_RE = /\.(png|jpe?g|gif|webp|bmp|svg)(\?|#|$)/i;
const PDF_EXT_RE = /\.pdf(\?|#|$)/i;

export function hasFileRef(value?: string | null) {
  return !!value && value !== 'placeholder';
}

export function isDataUrl(value: string) {
  return value.startsWith('data:');
}

export function isPdfFileRef(value?: string | null) {
  if (!hasFileRef(value)) return false;
  return value!.startsWith('data:application/pdf') || PDF_EXT_RE.test(value!);
}

export function isImageFileRef(value?: string | null) {
  if (!hasFileRef(value)) return false;
  return value!.startsWith('data:image/') || IMAGE_EXT_RE.test(value!);
}

function getExtension(value?: string | null) {
  if (!hasFileRef(value)) return '';
  if (value!.startsWith('data:application/pdf')) return 'pdf';
  if (value!.startsWith('data:image/png')) return 'png';
  if (value!.startsWith('data:image/jpeg') || value!.startsWith('data:image/jpg')) return 'jpg';
  const withoutHash = value!.split('#')[0];
  const withoutQuery = withoutHash.split('?')[0];
  const ext = withoutQuery.split('.').pop();
  return ext ? ext.toLowerCase() : '';
}

export function getSuggestedFilename(value: string, fallbackBase: string) {
  const ext = getExtension(value) || 'jpg';
  return `${fallbackBase}.${ext}`;
}

export function downloadFileRef(value: string, filename?: string) {
  const a = document.createElement('a');
  a.href = value;
  if (filename) a.download = filename;
  a.click();
}

async function blobToDataUrl(blob: Blob) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
}

export async function fileRefToDataUrl(value?: string | null) {
  if (!isImageFileRef(value)) return null;
  if (isDataUrl(value!)) return value!;

  const res = await fetch(value!);
  if (!res.ok) {
    throw new Error('Failed to load file');
  }

  return blobToDataUrl(await res.blob());
}
