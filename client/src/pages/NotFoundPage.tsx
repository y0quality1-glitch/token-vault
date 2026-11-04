import { useNavigate } from 'react-router-dom';
import { Compass } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/ui/feedback';

export function NotFoundPage() {
  const navigate = useNavigate();
  return <EmptyState icon={<Compass className="h-5 w-5" />} title="Page not found" description="The page you are looking for does not exist or was moved." action={<Button onClick={() => navigate('/')}>Back to overview</Button>} className="py-24" />;
}
