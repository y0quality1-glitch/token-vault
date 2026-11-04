import type { VersionStatus } from '@token-vault/shared';
import { Badge } from '@ui/badge';

const TONE = { DRAFT: 'gray', IN_REVIEW: 'amber', PUBLISHED: 'green', SUPERSEDED: 'blue' } as const;
const LABEL: Record<VersionStatus, string> = { DRAFT: 'Draft', IN_REVIEW: 'In review', PUBLISHED: 'Published', SUPERSEDED: 'Superseded' };

export function VersionBadge({ status }: { status: VersionStatus }) {
  return (
    <Badge tone={TONE[status]} dot>
      {LABEL[status]}
    </Badge>
  );
}
