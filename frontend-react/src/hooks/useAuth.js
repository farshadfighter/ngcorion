/* ==========================================
   NGCORION - useAuth Hook
   ========================================== */

import { useAppSelector } from '../store/hooks';

export const useAuth = () => {
  const { user, isAuthenticated, loading } = useAppSelector((state) => state.auth);

  const isAdmin = user?.role === 'admin';
  const isManager = user?.role === 'manager';
  const canWrite = isAdmin || isManager;
  const canDelete = isAdmin;

  // Check permission for a module
  const hasPermission = (module, action = 'read') => {
    if (isAdmin) return true;
    return user?.permissions?.[module]?.[action] === true;
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