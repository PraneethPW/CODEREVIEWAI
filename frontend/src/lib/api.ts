export const API = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('cra_token');
  const response = await fetch(API + path, {
    ...options,
    headers: {
      ...(options.body instanceof FormData ? {} : {'Content-Type': 'application/json'}),
      ...(token ? {Authorization: `Bearer ${token}`} : {}),
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({detail: 'Request failed'}));
    throw new Error(body.detail || 'Request failed');
  }
  return response.json();
}

export async function downloadArtifact(scanId: string) {
  const token = localStorage.getItem('cra_token');
  const response = await fetch(`${API}/scans/${scanId}/reviewed-file`, {
    headers: token ? {Authorization: `Bearer ${token}`} : {},
  });
  if (!response.ok) throw new Error('The reviewed artifact could not be downloaded.');
  const blob = await response.blob();
  const disposition = response.headers.get('content-disposition') || '';
  const filename = disposition.match(/filename="?([^";]+)"?/)?.[1] || 'codereview-fixed.zip';
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
