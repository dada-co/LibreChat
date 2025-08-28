export type Json = Record<string, unknown> | unknown[];

export async function getJSON(input: RequestInfo, init?: RequestInit): Promise<Json> {
  const res = await fetch(input, { credentials: 'include', ...init });
  const ct = res.headers.get('content-type') || '';
  const raw = await res.text();

  if (!res.ok) {
    const brief = raw.slice(0, 300);
    throw new Error(`${res.status} ${res.statusText}${brief ? `: ${brief}` : ''}`);
  }

  if (ct.includes('application/json')) {
    try {
      return JSON.parse(raw);
    } catch {
      throw new Error('Invalid JSON in successful response');
    }
  }

  // Non-JSON success: return empty object to keep callers safe
  return {};
}

export async function postJSON(url: string, body?: unknown, init?: RequestInit): Promise<Json> {
  return getJSON(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    body: body == null ? undefined : JSON.stringify(body),
    ...init,
  });
}
