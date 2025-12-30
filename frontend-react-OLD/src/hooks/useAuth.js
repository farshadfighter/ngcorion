/* ==========================================
   NGCORION - useAuth Hook
   ========================================== */

import { useAppSelector } from '../store/hooks';

export const useAuth = () => {
  const { user, isAuthenticated, loading } = useAppSelector((state) => state.auth);

  const isAdmin = user?.role === 'admin';
  const isManager = user?.role === 'manager';

  // Check permission for a module
  const hasPermission = (module, action = 'read') => {
    if (isAdmin) return true;
    return user?.permissions?.[module]?.[action] === true;
  };

  // Permission-based write/delete functions that check for specific module
  // Note: These are kept for backward compatibility but should use hasPermission() with module name
  const canWrite = (module = 'asset_list') => {
    if (isAdmin) return true;
    return user?.permissions?.[module]?.write === true;
  };

  const canDelete = (module = 'asset_list') => {
    if (isAdmin) return true;
    return user?.permissions?.[module]?.delete === true;
  };

  return {
    user,
    isAuthenticated,
    loading,
    isAdmin,
    isManager,
    canWrite,
    canDelete,
    hasPermission,
  };
};

export default useAuth;