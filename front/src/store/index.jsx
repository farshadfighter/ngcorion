import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./authSlice";
import userReducer from "./userSlice";
import assetReducer from "./assetSlice";
import requirementReducer from "./requirementSlice";
import discoveryReducer from "./discoverySlice";
<<<<<<< HEAD
import auditReducer from "./auditSlice";
=======
import hardeningReducer from "./hardeningSlice";
>>>>>>> 6d229e121da18fd32dcba0f9cd74367bfd1b0fd1

export const store = configureStore({
    reducer: {
        auth: authReducer,
        users: userReducer,
        assets: assetReducer,
        requirements: requirementReducer,
        discovery: discoveryReducer,
<<<<<<< HEAD
        audit: auditReducer,
=======
        hardening: hardeningReducer,
>>>>>>> 6d229e121da18fd32dcba0f9cd74367bfd1b0fd1
    },
});