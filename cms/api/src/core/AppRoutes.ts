/** Route prefixes, mounted under PATH (template: core/AppRoutes.ts). */
export enum APP_ROUTES {
  APIHEALTHCHECK = '/apiHealthCheck',
  AUTH = '/auth',
  APPLICATION = '/application',
  VERSION = '/version',
  AUDIT = '/audit',
}

export enum SUCCESSMSG {
  GET = 'Fetched Successfully',
  ADD = 'Added Successfully',
  UPDATE = 'Updated Successfully',
  DELETE = 'Deleted Successfully',
}
