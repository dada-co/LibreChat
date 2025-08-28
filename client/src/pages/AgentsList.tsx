import { useEffect, useState } from 'react';
import { getJSON } from '../lib/http-client';

export default function AgentsList() {
  const [agents, setAgents] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const data1 = await getJSON('/api/agents?requiredPermission=1');
        const data2 = await getJSON('/api/agents?requiredPermission=2');
        if (!mounted) return;

        const a1 = Array.isArray(data1) ? data1 : (data1 as any)?.items ?? [];
        const a2 = Array.isArray(data2) ? data2 : (data2 as any)?.items ?? [];
        setAgents([...a1, ...a2]);
      } catch (e: any) {
        console.error('Agents load failed:', e);
        if (!mounted) return;
        setError(e?.message ?? 'Failed to load agents');
        setAgents([]); // safe empty state
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => { mounted = false; };
  }, []);

  if (loading) return <div>Loading agents…</div>;

  return (
    <div>
      {error && (
        <div role="alert" className="text-sm text-red-500 mb-3">
          {error}
        </div>
      )}
      {agents.length === 0 ? (
        <div className="text-sm opacity-70">No agents available.</div>
      ) : (
        <ul className="space-y-2">
          {agents.map((a) => (
            <li key={a._id ?? a.id} className="border rounded p-2">
              <div className="font-medium">{a.name ?? '(unnamed agent)'}</div>
              <div className="text-xs opacity-70">{a.provider ?? '—'}</div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
