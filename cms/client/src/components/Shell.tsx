import { Blocks, KeyRound, LogOut, ScrollText } from 'lucide-react';
import { NavLink, Outlet } from 'react-router-dom';
import { Badge } from '@ui/badge';
import { ROLE_LABELS, useAuth } from '@/auth';
import { cn } from '@/lib/utils';

const NAV = [
  { to: '/applications', label: 'Applications', icon: Blocks },
  { to: '/audit', label: 'Audit log', icon: ScrollText },
  { to: '/catalog', label: 'Catalog & signing key', icon: KeyRound },
];

export function Shell() {
  const { user, logout } = useAuth();
  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-slate-200 bg-white md:flex">
        <div className="flex items-center gap-2.5 border-b border-slate-100 px-5 py-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600 text-white">
            <Blocks className="h-4 w-4" />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-900">Token Vault CMS</p>
            <p className="text-xs text-slate-500">Provider definitions</p>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 p-3">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) => cn('flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium', isActive ? 'bg-brand-50 text-brand-700' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900')}
            >
              <n.icon className="h-4 w-4" />
              {n.label}
            </NavLink>
          ))}
        </nav>
        {user && (
          <div className="border-t border-slate-100 p-4">
            <p className="truncate text-sm font-medium text-slate-900">{user.fullName}</p>
            <p className="truncate text-xs text-slate-500">{user.email}</p>
            <div className="mt-2 flex items-center justify-between">
              <Badge tone="violet">{ROLE_LABELS[user.role]}</Badge>
              <button onClick={() => void logout()} className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-900">
                <LogOut className="h-3.5 w-3.5" /> Sign out
              </button>
            </div>
          </div>
        )}
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 md:px-8">
        <div className="mx-auto max-w-6xl">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
