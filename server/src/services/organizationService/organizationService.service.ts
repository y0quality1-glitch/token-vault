import { transaction } from '../../databases/client';
import type { EmergencyStopDto, LiftEmergencyStopDto, OrganizationDto } from '../../databases/repository/organization/organization.dto';
import { conflict } from '../../lib/errors';
import { orgRepo } from '../../store/repos';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';

type OrgContext = AdminContext & { org: { id: string } };

/**
 * The current organization: its settings, and the emergency stop. One switch denies every agent
 * request in the organization (EMERGENCY_STOP) until it is lifted. Grants, keys and credentials
 * are left untouched, so lifting it restores access exactly as it was.
 */
export default class OrganizationService {
  update(ctx: OrgContext, body: OrganizationDto) {
    const fields = { name: body.name, environment: body.environment };
    return transaction(async (tx) => {
      const updated = await orgRepo.updateOrganization(ctx.org.id, { ...fields, updatedAt: new Date().toISOString() }, tx);
      await recordEvent({ orgId: updated.id, actor: userActor(ctx), eventType: 'organization.updated', target: { type: 'organization', id: updated.id, name: updated.name }, metadata: fields }, tx);
      return updated;
    });
  }

  async stopView(orgId: string) {
    const org = (await orgRepo.getOrganization(orgId))!;
    const byName = org.emergencyStoppedBy ? ((await orgRepo.userNames([org.emergencyStoppedBy])).get(org.emergencyStoppedBy) ?? 'Unknown user') : null;
    return { stopped: !!org.emergencyStoppedAt, stoppedAt: org.emergencyStoppedAt ?? null, stoppedBy: org.emergencyStoppedBy ?? null, stoppedByName: byName, reason: org.emergencyStopReason ?? null };
  }

  /** Stopping needs grant:revoke (checked by the controller). */
  async emergencyStop(ctx: OrgContext, { reason }: EmergencyStopDto) {
    await transaction(async (tx) => {
      const org = (await orgRepo.getOrganization(ctx.org.id, tx))!;
      if (org.emergencyStoppedAt) throw conflict('Agent access is already stopped');
      const now = new Date().toISOString();
      await orgRepo.updateOrganization(org.id, { emergencyStoppedAt: now, emergencyStoppedBy: ctx.user.id, emergencyStopReason: reason, updatedAt: now }, tx);
      await recordEvent({ orgId: org.id, actor: userActor(ctx), eventType: 'organization.emergency_stop', target: { type: 'organization', id: org.id, name: org.name }, severity: 'critical', metadata: { reason } }, tx);
    });
    return this.stopView(ctx.org.id);
  }

  /** Lifting (re-opening access) needs grant:approve (checked by the controller). */
  async liftEmergencyStop(ctx: OrgContext, { note }: LiftEmergencyStopDto) {
    await transaction(async (tx) => {
      const org = (await orgRepo.getOrganization(ctx.org.id, tx))!;
      if (!org.emergencyStoppedAt) throw conflict('Agent access is not stopped');
      await orgRepo.updateOrganization(org.id, { emergencyStoppedAt: null, emergencyStoppedBy: null, emergencyStopReason: null, updatedAt: new Date().toISOString() }, tx);
      await recordEvent({ orgId: org.id, actor: userActor(ctx), eventType: 'organization.emergency_stop_lifted', target: { type: 'organization', id: org.id, name: org.name }, severity: 'warning', metadata: { stoppedAt: org.emergencyStoppedAt, reason: org.emergencyStopReason, note } }, tx);
    });
    return this.stopView(ctx.org.id);
  }
}
