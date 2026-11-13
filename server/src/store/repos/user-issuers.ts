import type { UserIssuer } from '@token-vault/shared';
import { db, type Executor } from '../../databases/client';
import { UserIssuerEntity } from '../../entities';
import { deleteBy, insertRow, oneBy, updateBy } from './orm';

export async function listIssuers(organizationId: string, ex: Executor = db): Promise<UserIssuer[]> {
  return ex.find(UserIssuerEntity, { where: { organizationId }, order: { createdAt: 'ASC' } });
}

export async function getIssuer(organizationId: string, id: string, ex: Executor = db): Promise<UserIssuer | null> {
  return oneBy(ex, UserIssuerEntity, { organizationId, id });
}

export async function insertIssuer(record: UserIssuer, ex: Executor = db): Promise<UserIssuer> {
  return insertRow(ex, UserIssuerEntity, record, { id: record.id });
}

export async function updateIssuer(organizationId: string, id: string, patch: Partial<Omit<UserIssuer, 'id' | 'organizationId' | 'createdAt'>>, ex: Executor = db): Promise<UserIssuer | null> {
  return (await updateBy(ex, UserIssuerEntity, { organizationId, id }, patch)) ? oneBy(ex, UserIssuerEntity, { id }) : null;
}

export async function deleteIssuer(organizationId: string, id: string, ex: Executor = db): Promise<boolean> {
  return (await deleteBy(ex, UserIssuerEntity, { organizationId, id })) > 0;
}
