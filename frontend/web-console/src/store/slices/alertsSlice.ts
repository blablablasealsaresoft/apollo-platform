import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { Alert } from '@types/index';
import { dashboardService } from '@services/api';

interface AlertsState {
  alerts: Alert[];
  unreadCount: number;
  loading: boolean;
  error: string | null;
}

const initialState: AlertsState = {
  alerts: [],
  unreadCount: 0,
  loading: false,
  error: null,
};

export const fetchAlerts = createAsyncThunk('alerts/fetchAll', async () => {
  const response = await dashboardService.getAlerts();
  return response.data;
});

export const acknowledgeAlert = createAsyncThunk(
  'alerts/acknowledge',
  async (alertId: string) => {
    await dashboardService.acknowledgeAlert(alertId);
    return alertId;
  }
);

export const resolveAlert = createAsyncThunk(
  'alerts/resolve',
  async ({ alertId, notes }: { alertId: string; notes?: string }) => {
    await dashboardService.resolveAlert(alertId, notes);
    return alertId;
  }
);

const alertsSlice = createSlice({
  name: 'alerts',
  initialState,
  reducers: {
    addAlert: (state, action: PayloadAction<Alert>) => {
      state.alerts.unshift(action.payload);
      if (action.payload.status === 'new') {
        state.unreadCount += 1;
      }
    },
    updateAlert: (state, action: PayloadAction<Alert>) => {
      const index = state.alerts.findIndex((a) => a.id === action.payload.id);
      if (index !== -1) {
        state.alerts[index] = action.payload;
      }
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchAlerts.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchAlerts.fulfilled, (state, action) => {
        state.loading = false;
        state.alerts = action.payload || [];
        state.unreadCount = action.payload?.filter((a: Alert) => a.status === 'new').length || 0;
      })
      .addCase(fetchAlerts.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch alerts';
      })
      .addCase(acknowledgeAlert.fulfilled, (state, action) => {
        const alert = state.alerts.find((a) => a.id === action.payload);
        if (alert && alert.status === 'new') {
          alert.status = 'acknowledged';
          state.unreadCount -= 1;
        }
      })
      .addCase(resolveAlert.fulfilled, (state, action) => {
        const index = state.alerts.findIndex((a) => a.id === action.payload);
        if (index !== -1) {
          state.alerts.splice(index, 1);
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        }
      });
  },
});

export const { addAlert, updateAlert } = alertsSlice.actions;
export default alertsSlice.reducer;
