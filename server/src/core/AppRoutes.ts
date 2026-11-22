/** Admin API route prefixes, under PATH (/api/v1). */
export enum APP_ROUTES {
  APIHEALTHCHECK = '/apiHealthCheck',
  AUTH = '/auth',
  ORGANIZATION = '/organization',
  MEMBER = '/member',
  DASHBOARD = '/dashboard',
  WEBHOOK = '/webhook',
  PROVIDER = '/provider',
  INTEGRATION = '/integration',
  AGENT = '/agent',
  API_CLIENT = '/apiClient',
  GRANT = '/grant',
  GRANT_REQUEST = '/grantRequest',
  APPROVAL = '/approval',
  ACCESS_REVIEW = '/accessReview',
  POLICY = '/policy',
  USER_ISSUER = '/userIssuer',
  DELEGATION = '/delegation',
  SESSION = '/session',
  SLACK_SETTINGS = '/slackSettings',
  ACCESS_REQUEST = '/accessRequest',
  AUDIT_EVENT = '/auditEvent',
  DEMO = '/demo',
}

/** Agent API route prefixes, under AGENT_PATH (/agent/v1). */
export enum AGENT_ROUTES {
  REQUEST = '/request',
  CAPABILITY = '/capability',
  OPERATION = '/operation',
  ACCESS_REQUEST = '/accessRequest',
  APPROVAL = '/approval',
  DELEGATION = '/delegation',
}

export enum SUCCESSMSG {
  GET = 'Fetched Successfully',
  ADD = 'Added Successfully',
  UPDATE = 'Updated Successfully',
  DELETE = 'Deleted Successfully',
  DONE = 'Completed Successfully',
}
