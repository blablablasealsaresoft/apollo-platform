import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { AuthState, User } from '@types/index';
import { authService } from '@services/api';
import { wsClient } from '@services/websocket/client';

const initialState: AuthState = {
  user: null,
  token: localStorage.getItem('apollo_token'),
  refreshToken: localStorage.getItem('apollo_refresh_token'),
  isAuthenticated: !!localStorage.getItem('apollo_token'),
  loading: false,
  error: null,
};

export const login = createAsyncThunk(
  'auth/login',
  async (credentials: { username: string; password: string }, { rejectWithValue }) => {
    try {
      const response = await authService.login(credentials);
      return response.data;
    } catch (error: any) {
      return rejectWithValue(error.message || 'Login failed');
    }
  }
);

export const register = createAsyncThunk(
  'auth/register',
  async (data: any, { rejectWithValue }) => {
    try {
      const response = await authService.register(data);
      return response.data;
    } catch (error: any) {
      return rejectWithValue(error.message || 'Registration failed');
    }
  }
);

export const logout = createAsyncThunk('auth/logout', async (_, { rejectWithValue }) => {
  try {
    await authService.logout();
    wsClient.disconnect();
    return null;
  } catch (error: any) {
    return rejectWithValue(error.message || 'Logout failed');
  }
});

export const getCurrentUser = createAsyncThunk('auth/getCurrentUser', async (_, { rejectWithValue }) => {
  try {
    const response = await authService.getCurrentUser();
    return response.data;
  } catch (error: any) {
    return rejectWithValue(error.message || 'Failed to fetch user');
  }
});

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    setCredentials: (state, action: PayloadAction<{ user: User; token: string; refreshToken: string }>) => {
      state.user = action.payload.user;
      state.token = action.payload.token;
      state.refreshToken = action.payload.refreshToken;
      state.isAuthenticated = true;
      localStorage.setItem('apollo_token', action.payload.token);
      localStorage.setItem('apollo_refresh_token', action.payload.refreshToken);
      localStorage.setItem('apollo_user', JSON.stringify(action.payload.user));

      // Connect WebSocket
      wsClient.connect(action.payload.token);
    },
    clearCredentials: (state) => {
      state.user = null;
      state.token = null;
      state.refreshToken = null;
      state.isAuthenticated = false;
      localStorage.removeItem('apollo_token');
      localStorage.removeItem('apollo_refresh_token');
      localStorage.removeItem('apollo_user');

      // Disconnect WebSocket
      wsClient.disconnect();
    },
    updateUser: (state, action: PayloadAction<User>) => {
      state.user = action.payload;
      localStorage.setItem('apollo_user', JSON.stringify(action.payload));
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    // Login
    builder.addCase(login.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(login.fulfilled, (state, action) => {
      state.loading = false;
      state.user = action.payload.user;
      state.token = action.payload.token;
      state.refreshToken = action.payload.refreshToken;
      state.isAuthenticated = true;
      localStorage.setItem('apollo_token', action.payload.token);
      localStorage.setItem('apollo_refresh_token', action.payload.refreshToken);
      localStorage.setItem('apollo_user', JSON.stringify(action.payload.user));

      // Connect WebSocket
      wsClient.connect(action.payload.token);
    });
    builder.addCase(login.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
      state.isAuthenticated = false;
    });

    // Register
    builder.addCase(register.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(register.fulfilled, (state, action) => {
      state.loading = false;
      state.user = action.payload.user;
      state.token = action.payload.token;
      state.refreshToken = action.payload.refreshToken;
      state.isAuthenticated = true;
      localStorage.setItem('apollo_token', action.payload.token);
      localStorage.setItem('apollo_refresh_token', action.payload.refreshToken);
      localStorage.setItem('apollo_user', JSON.stringify(action.payload.user));

      // Connect WebSocket
      wsClient.connect(action.payload.token);
    });
    builder.addCase(register.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
    });

    // Logout
    builder.addCase(logout.fulfilled, (state) => {
      state.user = null;
      state.token = null;
      state.refreshToken = null;
      state.isAuthenticated = false;
      localStorage.removeItem('apollo_token');
      localStorage.removeItem('apollo_refresh_token');
      localStorage.removeItem('apollo_user');
    });

    // Get Current User
    builder.addCase(getCurrentUser.pending, (state) => {
      state.loading = true;
    });
    builder.addCase(getCurrentUser.fulfilled, (state, action) => {
      state.loading = false;
      state.user = action.payload;
      localStorage.setItem('apollo_user', JSON.stringify(action.payload));
    });
    builder.addCase(getCurrentUser.rejected, (state) => {
      state.loading = false;
      state.isAuthenticated = false;
      state.user = null;
      state.token = null;
      state.refreshToken = null;
      localStorage.removeItem('apollo_token');
      localStorage.removeItem('apollo_refresh_token');
      localStorage.removeItem('apollo_user');
    });
  },
});

export const { setCredentials, clearCredentials, updateUser, clearError } = authSlice.actions;
export default authSlice.reducer;
