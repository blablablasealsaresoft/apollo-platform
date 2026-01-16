import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { Operation } from '@types/index';
import { operationsService } from '@services/api';

interface OperationsState {
  operations: Operation[];
  currentOperation: Operation | null;
  loading: boolean;
  error: string | null;
}

const initialState: OperationsState = {
  operations: [],
  currentOperation: null,
  loading: false,
  error: null,
};

export const fetchOperations = createAsyncThunk('operations/fetchAll', async () => {
  const response = await operationsService.getAll();
  return response.data;
});

export const fetchOperationById = createAsyncThunk(
  'operations/fetchById',
  async (id: string) => {
    const response = await operationsService.getById(id);
    return response.data;
  }
);

export const createOperation = createAsyncThunk('operations/create', async (data: any) => {
  const response = await operationsService.create(data);
  return response.data;
});

const operationsSlice = createSlice({
  name: 'operations',
  initialState,
  reducers: {
    clearCurrentOperation: (state) => {
      state.currentOperation = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchOperations.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchOperations.fulfilled, (state, action) => {
        state.loading = false;
        state.operations = action.payload || [];
      })
      .addCase(fetchOperations.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch operations';
      })
      .addCase(fetchOperationById.fulfilled, (state, action) => {
        state.currentOperation = action.payload;
      })
      .addCase(createOperation.fulfilled, (state, action) => {
        state.operations.unshift(action.payload);
      });
  },
});

export const { clearCurrentOperation } = operationsSlice.actions;
export default operationsSlice.reducer;
