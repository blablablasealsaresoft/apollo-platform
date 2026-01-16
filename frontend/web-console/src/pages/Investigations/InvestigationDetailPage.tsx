import React, { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchInvestigationById } from '@store/slices/investigationsSlice';

const InvestigationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const dispatch = useAppDispatch();
  const { currentInvestigation, loading } = useAppSelector((state) => state.investigations);

  useEffect(() => {
    if (id) {
      dispatch(fetchInvestigationById(id));
    }
  }, [id, dispatch]);

  if (loading) return <div className="flex justify-center py-12"><div className="spinner"></div></div>;
  if (!currentInvestigation) return <div>Investigation not found</div>;

  return (
    <div className="space-y-6">
      <div className="card">
        <h1 className="text-2xl font-bold">{currentInvestigation.title}</h1>
        <p className="mt-2 text-gray-600">{currentInvestigation.description}</p>
        <div className="mt-4 grid grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-gray-500">Case Number</p>
            <p className="font-mono">{currentInvestigation.caseNumber}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Status</p>
            <p className="font-medium">{currentInvestigation.status}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Priority</p>
            <p className="font-medium">{currentInvestigation.priority}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Lead Investigator</p>
            <p>{currentInvestigation.leadInvestigator.firstName} {currentInvestigation.leadInvestigator.lastName}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default InvestigationDetailPage;
