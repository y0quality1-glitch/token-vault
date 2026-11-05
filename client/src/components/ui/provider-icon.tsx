import { BarChart3, Bot, Briefcase, Calendar, Cloud, CreditCard, Database, FileText, GitBranch, Github, Mail, MessageSquare, Plug, Shield, Ticket, Users, type LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

/**
 * Icons a provider definition may name (catalog.icon). A fixed set, rendered locally:
 * definitions never make the console load remote images.
 */
const ICONS: Record<string, LucideIcon> = {
  plug: Plug,
  github: Github,
  mail: Mail,
  calendar: Calendar,
  'message-square': MessageSquare,
  bot: Bot,
  ticket: Ticket,
  database: Database,
  cloud: Cloud,
  'file-text': FileText,
  'credit-card': CreditCard,
  users: Users,
  shield: Shield,
  'git-branch': GitBranch,
  briefcase: Briefcase,
  'bar-chart': BarChart3,
};

export function ProviderIcon({ name, className }: { name?: string | null; className?: string }) {
  const Icon = (name && ICONS[name]) || Plug;
  return <Icon className={cn('h-6 w-6', className)} aria-hidden />;
}
