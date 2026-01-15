import { configureStore } from '@reduxjs/toolkit';
import { persistStore, persistReducer } from 'redux-persist';
import storage from 'redux-persist/lib/storage';
import { combineReducers } from 'redux';

import authReducer from './slices/authSlice';
import investigationsReducer from './slices/investigationsSlice';
import targetsReducer from './slices/targetsSlice';
import evidenceReducer from './slices/evidenceSlice';
import alertsReducer from './slices/alertsSlice';
import operationsReducer from './slices/operationsSlice';

const persistConfig = {
  key: 'apollo-root',
  storage,
  whitelist: ['auth'], // Only persist auth state
};

const rootReducer = combineReducers({
  auth: authReducer,
  investigations: investigationsReducer,
  targets: targetsReducer,
  evidence: evidenceReducer,
  alerts: alertsReducer,
  operations: operationsReducer,
});

const persistedReducer = persistReducer(persistConfig, rootReducer);

export const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST', 'persist/REHYDRATE'],
      },
    }),
  devTools: process.env.NODE_ENV !== 'production',
});

export const persistor = persistStore(store);

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
