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

  return {
    user,
    isAuthenticated,
    loading,
    isAdmin,
    isManager,
    canWrite,
    canDelete,
  };
};

export default useAuth;
