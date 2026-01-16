import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { Target } from '@types/index';
import { targetsService } from '@services/api';

interface TargetsState {
  targets: Target[];
  currentTarget: Target | null;
  loading: boolean;
  error: string | null;
}

const initialState: TargetsState = {
  targets: [],
  currentTarget: null,
  loading: false,
  error: null,
};

export const fetchTargets = createAsyncThunk('targets/fetchAll', async () => {
  const response = await targetsService.getAll();
  return response.data;
});

export const fetchTargetById = createAsyncThunk('targets/fetchById', async (id: string) => {
  const response = await targetsService.getById(id);
  return response.data;
});

export const createTarget = createAsyncThunk('targets/create', async (data: any) => {
  const response = await targetsService.create(data);
  return response.data;
});

export const updateTarget = createAsyncThunk(
  'targets/update',
  async ({ id, data }: { id: string; data: any }) => {
    const response = await targetsService.update(id, data);
    return response.data;
  }
);

const targetsSlice = createSlice({
  name: 'targets',
  initialState,
  reducers: {
    clearCurrentTarget: (state) => {
      state.currentTarget = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchTargets.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchTargets.fulfilled, (state, action) => {
        state.loading = false;
        state.targets = action.payload || [];
      })
      .addCase(fetchTargets.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch targets';
      })
      .addCase(fetchTargetById.fulfilled, (state, action) => {
        state.currentTarget = action.payload;
      })
      .addCase(createTarget.fulfilled, (state, action) => {
        state.targets.unshift(action.payload);
      })
      .addCase(updateTarget.fulfilled, (state, action) => {
        const index = state.targets.findIndex((t) => t.id === action.payload.id);
        if (index !== -1) state.targets[index] = action.payload;
        if (state.currentTarget?.id === action.payload.id) state.currentTarget = action.payload;
      });
  },
});

export const { clearCurrentTarget } = targetsSlice.actions;
export default targetsSlice.reducer;
