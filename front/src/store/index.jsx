import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./authSlice";
import userReducer from "./userSlice";
import assetReducer from "./assetSlice";
import requirementReducer from "./requirementSlice";
import discoveryReducer from "./discoverySlice";
import hardeningReducer from "./hardeningSlice";

export const store = configureStore({
    reducer: {
        auth: authReducer,
        users: userReducer,
        assets: assetReducer,
        requirements: requirementReducer,
        discovery: discoveryReducer,
        hardening: hardeningReducer,
    },
});