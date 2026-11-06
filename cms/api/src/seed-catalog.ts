import type { ProviderDefinitionInput } from '@token-vault/shared';

/**
 * Catalog entries the CMS seeds as "coming soon": listed in Token Vault's Integration
 * Catalog, not connectable yet. They are ordinary definitions: edit them (Edit starts a
 * new draft), publish it with availability "available" once ready, or archive them. Each
 * operation has a simulated response for mock mode (the default), so demo calls return data.
 */
export const COMING_SOON_DEFINITIONS: ProviderDefinitionInput[] = [
  {
    key: 'google',
    version: 1,
    name: 'Google Workspace',
    description: 'Drive, Calendar and Gmail APIs.',
    catalog: { category: 'Productivity', icon: 'calendar', availability: 'coming_soon', docsUrl: 'https://developers.google.com/workspace', tags: ['calendar', 'drive', 'mail'] },
    api: { baseUrl: 'https://www.googleapis.com', allowedHosts: ['www.googleapis.com', 'oauth2.googleapis.com'] },
    resource: { name: 'calendar', label: 'Calendar', pattern: '^[A-Za-z0-9._@-]{1,200}$', example: 'primary' },
    auth: [
      {
        id: 'OAUTH',
        label: 'Sign in with Google',
        kind: 'oauth2',
        oauth: {
          authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
          tokenUrl: 'https://oauth2.googleapis.com/token',
          scopes: ['https://www.googleapis.com/auth/calendar.readonly'],
          authorizeParams: { access_type: 'offline', prompt: 'consent' },
        },
      },
    ],
    credentialTest: { request: { method: 'GET', path: '/calendar/v3/users/me/calendarList', query: { maxResults: 1 } }, response: { fields: { kind: 'kind' } } },
    operations: [
      {
        id: 'google.events.list',
        label: 'List calendar events',
        risk: 'read',
        request: { method: 'GET', path: '/calendar/v3/calendars/{resource.calendar}/events', query: { maxResults: 10 } },
        response: { fields: { items: 'items' } },
        mock: { status: 200, body: { kind: 'calendar#events', items: [{ id: 'evt1', summary: 'Team standup', start: { dateTime: '2026-01-05T09:00:00Z' } }] } },
      },
    ],
  },
  {
    key: 'slack',
    version: 1,
    name: 'Slack',
    description: 'Post messages and read channels with a bot token.',
    catalog: { category: 'Communication', icon: 'message-square', availability: 'coming_soon', docsUrl: 'https://api.slack.com/methods', tags: ['chat'] },
    api: { baseUrl: 'https://slack.com/api', allowedHosts: ['slack.com'] },
    resource: { name: 'channel', label: 'Channel', pattern: '^[CG][A-Z0-9]{8,12}$', example: 'C0123456789' },
    auth: [{ id: 'BOT_TOKEN', label: 'Bot token', kind: 'bearer', secretPattern: '^xoxb-[A-Za-z0-9-]{20,}$', secretHint: 'Starts with xoxb-' }],
    credentialTest: { request: { method: 'POST', path: '/auth.test' }, response: { fields: { ok: 'ok', team: 'team' } } },
    operations: [
      {
        id: 'slack.messages.post',
        label: 'Post a message',
        risk: 'write',
        input: { text: { type: 'string', required: true, maxLength: 4000 } },
        request: { method: 'POST', path: '/chat.postMessage', body: { channel: '{resource.channel}', text: '{input.text}' } },
        response: { fields: { ok: 'ok', ts: 'ts' } },
        mock: { status: 200, body: { ok: true, channel: 'C0123456789', ts: '1767600000.000100' } },
      },
    ],
  },
  {
    key: 'openai',
    version: 1,
    name: 'OpenAI',
    description: 'Model inference with an organization API key.',
    catalog: { category: 'AI', icon: 'bot', availability: 'coming_soon', docsUrl: 'https://platform.openai.com/docs/api-reference', tags: ['llm'] },
    api: { baseUrl: 'https://api.openai.com/v1', allowedHosts: ['api.openai.com'] },
    resource: { name: 'model', label: 'Model', pattern: '^[a-z0-9.:-]{2,80}$', example: 'gpt-4o-mini' },
    auth: [{ id: 'API_KEY', label: 'API key', kind: 'bearer', secretPattern: '^sk-[A-Za-z0-9_-]{20,}$', secretHint: 'Starts with sk-' }],
    credentialTest: { request: { method: 'GET', path: '/models' }, response: { fields: { object: 'object' } } },
    operations: [{ id: 'openai.models.read', label: 'Read a model', risk: 'read', request: { method: 'GET', path: '/models/{resource.model}' }, response: { fields: { id: 'id', owned_by: 'owned_by' } }, mock: { status: 200, body: { id: 'gpt-4o-mini', object: 'model', owned_by: 'openai' } } }],
  },
];
