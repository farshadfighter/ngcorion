/* ==========================================
   NGCORION - Redux Hooks
   ========================================== */

import { useDispatch, useSelector } from 'react-redux';

// Typed hooks for better development experience
export const useAppDispatch = () => useDispatch();
export const useAppSelector = useSelector;
