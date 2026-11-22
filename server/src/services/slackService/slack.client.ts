import { config } from '../../config';

/**
 * Minimal Slack Web API client (only what approvals need). SLACK_API_URL points it at a
 * stand-in for tests. Never logs tokens.
 */
export class SlackApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

async function call<T>(method: string, token: string, body: Record<string, unknown>): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${config.slackApiUrl}/${method}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    throw new SlackApiError('unreachable', 'Slack could not be reached.');
  }
  const json = (await res.json().catch(() => null)) as ({ ok: boolean; error?: string } & T) | null;
  if (!json) throw new SlackApiError('bad_response', `Slack answered HTTP ${res.status} without JSON.`);
  if (!json.ok) throw new SlackApiError(json.error ?? 'unknown_error', `Slack refused ${method}: ${json.error ?? 'unknown error'}.`);
  return json;
}

export const slack = {
  /** Who the token belongs to: workspace and bot user. */
  authTest: (token: string) => call<{ team_id: string; team: string; user_id: string }>('auth.test', token, {}),
  postMessage: (token: string, body: { channel: string; text: string; blocks: unknown[] }) => call<{ channel: string; ts: string }>('chat.postMessage', token, body),
  update: (token: string, body: { channel: string; ts: string; text: string; blocks: unknown[] }) => call<{ ts: string }>('chat.update', token, body),
  /** Needs the users:read.email scope: the email maps a Slack user to a Token Vault user. */
  userEmail: async (token: string, user: string) => (await call<{ user: { profile?: { email?: string } } }>('users.info', token, { user })).user.profile?.email ?? null,
};

/** Replies through an interaction's response_url (replaces the message, or answers only the clicker). */
export async function respond(responseUrl: string, body: Record<string, unknown>): Promise<void> {
  // Only Slack's own hooks host (or the configured stand-in) is called with interaction replies.
  const allowed = new URL(config.slackApiUrl).origin;
  const target = new URL(responseUrl);
  if (target.origin !== allowed && target.hostname !== 'hooks.slack.com') return;
  await fetch(responseUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
}
