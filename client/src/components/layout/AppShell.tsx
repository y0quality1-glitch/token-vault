import { useEffect, useRef, useState } from 'react';
import { loadProviders } from '@/lib/providers';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  BookOpen,
  Bot,
  Building2,
  ChevronDown,
  FlaskConical,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Plug,
  Settings,
  ShieldCheck,
  Webhook,
  X,
} from 'lucide-react';
import { ROLE_LABELS } from '@token-vault/shared';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/components/ui/toast';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import { EmergencyStopBanner } from '@/components/EmergencyStop';

interface NavGroup {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  to?: string;
  children?: { label: string; to: string; badge?: 'pendingRequests' | 'reviewsDue' | 'pendingApprovals' }[];
  badge?: string;
}

const NAV: NavGroup[] = [
  { label: 'Overview', icon: LayoutDashboard, to: '/' },
  {
    label: 'Integrations',
    icon: Plug,
    children: [
      { label: 'Integration Catalog', to: '/integrations/catalog' },
      { label: 'Connected Integrations', to: '/integrations/connected' },
      { label: 'Credential Status', to: '/integrations/credentials' },
    ],
  },
  { label: 'Agents', icon: Bot, children: [{ label: 'Agent Registry', to: '/agents' }] },
  {
    label: 'Access Management',
    icon: KeyRound,
    children: [
      { label: 'Access Grants', to: '/access/grants' },
      { label: 'Access Requests', to: '/access/requests', badge: 'pendingRequests' },
      { label: 'Approvals', to: '/access/approvals', badge: 'pendingApprovals' },
      { label: 'Access Reviews', to: '/access/reviews', badge: 'reviewsDue' },
      { label: 'Policies', to: '/access/policies' },
    ],
  },
  { label: 'Access Playground', icon: FlaskConical, to: '/playground', badge: 'Demo' },
  {
    label: 'Webhook / Vault Agent',
    icon: Webhook,
    children: [
      { label: 'Webhook Setup', to: '/webhook/setup' },
      { label: 'Health & Connectivity', to: '/webhook/health' },
    ],
  },
  {
    label: 'Audit & Activity',
    icon: Activity,
    children: [
      { label: 'Access Logs', to: '/audit/access-logs' },
      { label: 'Sessions', to: '/audit/sessions' },
      { label: 'Security Events', to: '/audit/security-events' },
    ],
  },
  {
    label: 'Settings',
    icon: Settings,
    children: [
      { label: 'Organization', to: '/settings/organization' },
      { label: 'Members & Roles', to: '/settings/members' },
      { label: 'API Clients', to: '/settings/api-clients' },
      { label: 'User Identity', to: '/settings/user-identity' },
      { label: 'Slack approvals', to: '/settings/slack' },
    ],
  },
];

/** Sidebar counts (pending access requests and approvals, grants due for review), refreshed on navigation and every 30 s. */
function useNavCounts(pathname: string): { pendingRequests: number; reviewsDue: number; pendingApprovals: number } {
  const [counts, setCounts] = useState({ pendingRequests: 0, reviewsDue: 0, pendingApprovals: 0 });
  useEffect(() => {
    let cancelled = false;
    const load = () =>
      Promise.all([api.get<{ pending: number }>('/grant-requests?status=PENDING'), api.get<{ due: number }>('/access-reviews?summary=1'), api.get<{ pending: number }>('/approvals?status=PENDING')])
        .then(([r, v, a]) => !cancelled && setCounts({ pendingRequests: r.pending, reviewsDue: v.due, pendingApprovals: a.pending }))
        .catch(() => undefined);
    void load();
    const t = setInterval(load, 30_000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [pathname]);
  return counts;
}

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { pathname } = useLocation();
  const navCounts = useNavCounts(pathname);
  return (
    <div className="flex h-full flex-col bg-slate-950 text-slate-300">
      <div className="flex h-14 items-center gap-2.5 border-b border-white/10 px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600">
          <ShieldCheck className="h-5 w-5 text-white" />
        </div>
        <div>
          <p className="text-sm font-semibold text-white">Token Vault</p>
          <p className="text-[10px] uppercase tracking-wider text-slate-500">Proof of concept</p>
        </div>
      </div>
      <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
        {NAV.map((g) =>
          g.to ? (
            <NavLink
              key={g.label}
              to={g.to}
              end={g.to === '/'}
              onClick={onNavigate}
              className={({ isActive }) => cn('flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm font-medium transition', isActive ? 'bg-white/10 text-white' : 'hover:bg-white/5 hover:text-white')}
            >
              <g.icon className="h-4 w-4" />
              <span className="flex-1">{g.label}</span>
              {g.badge && <span className="rounded bg-violet-500/20 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-violet-300">{g.badge}</span>}
            </NavLink>
          ) : (
            <div key={g.label}>
              <p className={cn('mb-1 flex items-center gap-2.5 px-2.5 text-xs font-semibold uppercase tracking-wider', g.children?.some((c) => pathname.startsWith(c.to)) ? 'text-slate-200' : 'text-slate-500')}>
                <g.icon className="h-3.5 w-3.5" />
                {g.label}
              </p>
              <div className="space-y-0.5">
                {g.children!.map((c) => (
                  <NavLink
                    key={c.to}
                    to={c.to}
                    end={c.to === '/agents' ? false : undefined}
                    onClick={onNavigate}
                    className={({ isActive }) => cn('block rounded-md py-1.5 pl-9 pr-2.5 text-sm transition', isActive ? 'bg-white/10 font-medium text-white' : 'text-slate-400 hover:bg-white/5 hover:text-white')}
                  >
                    <span className="flex items-center justify-between gap-2">
                      {c.label}
                      {c.badge && navCounts[c.badge] > 0 && (
                        <span className="rounded-full bg-amber-500 px-1.5 text-[10px] font-semibold leading-4 text-white" aria-label={`${navCounts[c.badge]} ${c.badge === 'reviewsDue' ? 'due' : 'pending'}`}>
                          {navCounts[c.badge]}
                        </span>
                      )}
                    </span>
                  </NavLink>
                ))}
              </div>
            </div>
          ),
        )}
      </nav>
      <div className="border-t border-white/10 p-3">
        <NavLink to="/guide" onClick={onNavigate} className={({ isActive }) => cn('flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition', isActive ? 'bg-white/10 text-white' : 'text-slate-400 hover:bg-white/5 hover:text-white')}>
          <BookOpen className="h-4 w-4" /> Demo guide
        </NavLink>
      </div>
    </div>
  );
}

function useClickOutside(ref: React.RefObject<HTMLElement | null>, onOutside: () => void) {
  useEffect(() => {
    const h = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && onOutside();
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [ref, onOutside]);
}

function Header({ onMenu }: { onMenu: () => void }) {
  const { session, logout, selectOrganization } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const [orgOpen, setOrgOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const orgRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);
  useClickOutside(orgRef, () => setOrgOpen(false));
  useClickOutside(userRef, () => setUserOpen(false));
  if (!session) return null;
  const org = session.currentOrganization!;

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-slate-200 bg-white/90 px-4 backdrop-blur sm:px-6">
      <button className="rounded p-1.5 text-slate-500 hover:bg-slate-100 lg:hidden" onClick={onMenu} aria-label="Open navigation">
        <Menu className="h-5 w-5" />
      </button>

      <div className="relative" ref={orgRef}>
        <button onClick={() => setOrgOpen((o) => !o)} className="flex items-center gap-2 rounded-md border border-slate-200 px-2.5 py-1.5 text-sm hover:bg-slate-50">
          <Building2 className="h-4 w-4 text-slate-400" />
          <span className="max-w-[10rem] truncate font-medium text-slate-800">{org.name}</span>
          <span className="hidden rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium uppercase text-slate-500 sm:inline">{org.environment}</span>
          <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
        </button>
        {orgOpen && (
          <div className="absolute left-0 top-full mt-1 w-72 animate-fade-in rounded-lg border border-slate-200 bg-white p-1 shadow-lg">
            <p className="px-3 py-2 text-xs font-medium uppercase tracking-wide text-slate-400">Switch organization</p>
            {session.memberships.map((m) => (
              <button
                key={m.organizationId}
                onClick={async () => {
                  setOrgOpen(false);
                  if (m.organizationId === org.id) return;
                  await selectOrganization(m.organizationId);
                  toast.info(`Switched to ${m.organizationName}`);
                  navigate('/');
                }}
                className={cn('flex w-full items-center justify-between rounded-md px-3 py-2 text-left text-sm hover:bg-slate-50', m.organizationId === org.id && 'bg-brand-50')}
              >
                <span>
                  <span className="block font-medium text-slate-800">{m.organizationName}</span>
                  <span className="block text-xs text-slate-500">{ROLE_LABELS[m.role]}</span>
                </span>
                {m.organizationId === org.id && <span className="text-xs font-medium text-brand-700">Current</span>}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="flex-1" />

      <span className="hidden items-center gap-1.5 rounded-full bg-violet-50 px-2.5 py-1 text-xs font-medium text-violet-700 ring-1 ring-inset ring-violet-600/20 md:inline-flex" title="Upstream GitHub calls are simulated by the customer webhook (GITHUB_MODE=mock). Authorization, signing and encryption are real code paths but not production-hardened.">
        <FlaskConical className="h-3.5 w-3.5" /> POC · simulated provider
      </span>

      <div className="relative" ref={userRef}>
        <button onClick={() => setUserOpen((o) => !o)} className="flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-slate-50">
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-100 text-xs font-semibold text-brand-700">
            {session.user.fullName
              .split(' ')
              .map((p) => p[0])
              .join('')}
          </span>
          <span className="hidden text-left sm:block">
            <span className="block text-sm font-medium leading-tight text-slate-800">{session.user.fullName}</span>
            <span className="block text-xs leading-tight text-slate-500">{session.role ? ROLE_LABELS[session.role] : ''}</span>
          </span>
          <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
        </button>
        {userOpen && (
          <div className="absolute right-0 top-full mt-1 w-56 animate-fade-in rounded-lg border border-slate-200 bg-white p-1 shadow-lg">
            <div className="border-b border-slate-100 px-3 py-2">
              <p className="truncate text-sm font-medium text-slate-800">{session.user.email}</p>
              <p className="text-xs text-slate-500">{session.role ? ROLE_LABELS[session.role] : ''}</p>
            </div>
            <button
              onClick={async () => {
                await logout();
                navigate('/login');
              }}
              className="mt-1 flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
            >
              <LogOut className="h-4 w-4" /> Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { pathname } = useLocation();
  const orgId = useAuth().session?.currentOrganization?.id;
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);
  // Providers can change at runtime (published in the CMS): refresh on navigation.
  useEffect(() => {
    if (orgId) void loadProviders().catch(() => undefined);
  }, [orgId, pathname]);
  return (
    <div className="min-h-screen bg-slate-50">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 lg:block">
        <Sidebar />
      </aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-slate-900/50" onClick={() => setMobileOpen(false)} />
          <div className="absolute inset-y-0 left-0 w-64 animate-slide-in">
            <Sidebar onNavigate={() => setMobileOpen(false)} />
            <button onClick={() => setMobileOpen(false)} className="absolute right-2 top-3 rounded p-1 text-slate-400 hover:text-white" aria-label="Close navigation">
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>
      )}
      <div className="lg:pl-64">
        <Header onMenu={() => setMobileOpen(true)} />
        <EmergencyStopBanner />
        <main className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
