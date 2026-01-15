import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { Investigation, FilterOptions, SortOptions, PaginationOptions } from '@types/index';
import { investigationsService } from '@services/api';

interface InvestigationsState {
  investigations: Investigation[];
  currentInvestigation: Investigation | null;
  loading: boolean;
  error: string | null;
  filters: FilterOptions;
  sort: SortOptions;
  pagination: PaginationOptions;
  totalCount: number;
}

const initialState: InvestigationsState = {
  investigations: [],
  currentInvestigation: null,
  loading: false,
  error: null,
  filters: {},
  sort: { field: 'updatedAt', direction: 'desc' },
  pagination: { page: 1, pageSize: 20 },
  totalCount: 0,
};

export const fetchInvestigations = createAsyncThunk(
  'investigations/fetchAll',
  async (_, { getState, rejectWithValue }) => {
    try {
      const state = getState() as { investigations: InvestigationsState };
      const response = await investigationsService.getAll(
        state.investigations.filters,
        state.investigations.sort,
        state.investigations.pagination
      );
      return response;
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

export const fetchInvestigationById = createAsyncThunk(
  'investigations/fetchById',
  async (id: string, { rejectWithValue }) => {
    try {
      const response = await investigationsService.getById(id);
      return response.data;
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

export const createInvestigation = createAsyncThunk(
  'investigations/create',
  async (data: any, { rejectWithValue }) => {
    try {
      const response = await investigationsService.create(data);
      return response.data;
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

export const updateInvestigation = createAsyncThunk(
  'investigations/update',
  async ({ id, data }: { id: string; data: any }, { rejectWithValue }) => {
    try {
      const response = await investigationsService.update(id, data);
      return response.data;
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

export const deleteInvestigation = createAsyncThunk(
  'investigations/delete',
  async (id: string, { rejectWithValue }) => {
    try {
      await investigationsService.delete(id);
      return id;
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

const investigationsSlice = createSlice({
  name: 'investigations',
  initialState,
  reducers: {
    setFilters: (state, action: PayloadAction<FilterOptions>) => {
      state.filters = action.payload;
      state.pagination.page = 1;
    },
    setSort: (state, action: PayloadAction<SortOptions>) => {
      state.sort = action.payload;
    },
    setPagination: (state, action: PayloadAction<PaginationOptions>) => {
      state.pagination = action.payload;
    },
    clearCurrentInvestigation: (state) => {
      state.currentInvestigation = null;
    },
    updateInvestigationInList: (state, action: PayloadAction<Investigation>) => {
      const index = state.investigations.findIndex((inv) => inv.id === action.payload.id);
      if (index !== -1) {
        state.investigations[index] = action.payload;
      }
      if (state.currentInvestigation?.id === action.payload.id) {
        state.currentInvestigation = action.payload;
      }
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchInvestigations.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchInvestigations.fulfilled, (state, action) => {
        state.loading = false;
        state.investigations = action.payload.data || [];
        state.totalCount = action.payload.pagination?.totalItems || 0;
      })
      .addCase(fetchInvestigations.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      .addCase(fetchInvestigationById.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchInvestigationById.fulfilled, (state, action) => {
        state.loading = false;
        state.currentInvestigation = action.payload;
      })
      .addCase(fetchInvestigationById.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      .addCase(createInvestigation.fulfilled, (state, action) => {
        state.investigations.unshift(action.payload);
        state.totalCount += 1;
      })
      .addCase(updateInvestigation.fulfilled, (state, action) => {
        const index = state.investigations.findIndex((inv) => inv.id === action.payload.id);
        if (index !== -1) {
          state.investigations[index] = action.payload;
        }
        if (state.currentInvestigation?.id === action.payload.id) {
          state.currentInvestigation = action.payload;
        }
      })
      .addCase(deleteInvestigation.fulfilled, (state, action) => {
        state.investigations = state.investigations.filter((inv) => inv.id !== action.payload);
        state.totalCount -= 1;
      });
  },
});

export const {
  setFilters,
  setSort,
  setPagination,
  clearCurrentInvestigation,
  updateInvestigationInList,
} = investigationsSlice.actions;

export default investigationsSlice.reducer;
