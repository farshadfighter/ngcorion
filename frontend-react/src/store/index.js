/* ==========================================
   NGCORION - Redux Store Configuration
   ========================================== */

import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import usersReducer from './slices/usersSlice';
import assetsReducer from './slices/assetsSlice';
import assetTypesReducer from './slices/assetTypesSlice';
import ownersReducer from './slices/ownersSlice';
import locationsReducer from './slices/locationsSlice';
import zonesReducer from './slices/zonesSlice';
import osCatalogReducer from './slices/osCatalogSlice';
import vendorsReducer from './slices/vendorsSlice';
import enumsReducer from './slices/enumsSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    users: usersReducer,
    assets: assetsReducer,
    assetTypes: assetTypesReducer,
    owners: ownersReducer,
    locations: locationsReducer,
    zones: zonesReducer,
    osCatalog: osCatalogReducer,
    vendors: vendorsReducer,
    enums: enumsReducer,
  },
  devTools: import.meta.env.DEV,
});

export default store;
