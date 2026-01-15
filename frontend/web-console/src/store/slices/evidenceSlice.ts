import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { Evidence } from '@types/index';
import { evidenceService } from '@services/api';

interface EvidenceState {
  evidence: Evidence[];
  currentEvidence: Evidence | null;
  loading: boolean;
  error: string | null;
}

const initialState: EvidenceState = {
  evidence: [],
  currentEvidence: null,
  loading: false,
  error: null,
};

export const fetchEvidence = createAsyncThunk('evidence/fetchAll', async () => {
  const response = await evidenceService.getAll();
  return response.data;
});

export const fetchEvidenceByInvestigation = createAsyncThunk(
  'evidence/fetchByInvestigation',
  async (investigationId: string) => {
    const response = await evidenceService.getByInvestigation(investigationId);
    return response.data;
  }
);

export const createEvidence = createAsyncThunk(
  'evidence/create',
  async ({ data, file }: { data: any; file?: File }) => {
    const response = await evidenceService.create(data, file);
    return response.data;
  }
);

const evidenceSlice = createSlice({
  name: 'evidence',
  initialState,
  reducers: {
    clearCurrentEvidence: (state) => {
      state.currentEvidence = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchEvidence.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchEvidence.fulfilled, (state, action) => {
        state.loading = false;
        state.evidence = action.payload || [];
      })
      .addCase(fetchEvidence.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch evidence';
      })
      .addCase(fetchEvidenceByInvestigation.fulfilled, (state, action) => {
        state.evidence = action.payload || [];
      })
      .addCase(createEvidence.fulfilled, (state, action) => {
        state.evidence.unshift(action.payload);
      });
  },
});

export const { clearCurrentEvidence } = evidenceSlice.actions;
export default evidenceSlice.reducer;
