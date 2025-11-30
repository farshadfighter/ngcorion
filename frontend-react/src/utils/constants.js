/* ==========================================
   NGCORION - Constants
   ========================================== */

export const ROUTES = {
  LOGIN: '/login',
  DASHBOARD: '/dashboard',
  USERS: '/users',
  ASSET_LIST: '/assets',
  ASSET_REQUIREMENT: '/asset-requirement',
};

export const USER_ROLES = {
  ADMIN: 'admin',
  MANAGER: 'manager',
  USER: 'user',
  GUEST: 'guest',
};

export const ASSET_VIEWS = {
  OVERVIEW: 'overview',
  NETWORK: 'network',
  LOCATION: 'location',
  PORTS: 'ports',
  SECURITY: 'security',
};

export const STATUS_COLORS = {
  active: 'success',
  standby: 'warning',
  decommissioned: 'secondary',
  unknown: 'muted',
};

export const RISK_COLORS = {
  low: 'success',
  medium: 'warning',
  high: 'danger',
  critical: 'danger',
};

export const CONFIDENTIALITY_COLORS = {
  public: 'secondary',
  internal: 'info',
  confidential: 'warning',
  critical: 'danger',
};
