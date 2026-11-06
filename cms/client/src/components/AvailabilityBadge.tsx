import { Badge } from '@ui/badge';

/** How an application appears in Token Vault's Integration Catalog. */
export function AvailabilityBadge({ availability }: { availability: 'available' | 'coming_soon' }) {
  return availability === 'coming_soon' ? (
    <Badge tone="amber">Coming soon</Badge>
  ) : (
    <Badge tone="green">Available</Badge>
  );
}
