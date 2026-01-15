import React, { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchOperationById } from '@store/slices/operationsSlice';

const OperationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const dispatch = useAppDispatch();
  const { currentOperation, loading } = useAppSelector((state) => state.operations);

  useEffect(() => {
    if (id) dispatch(fetchOperationById(id));
  }, [id, dispatch]);

  if (loading) return <div className="flex justify-center py-12"><div className="spinner"></div></div>;
  if (!currentOperation) return <div>Operation not found</div>;

  return (
    <div className="space-y-6">
      <div className="card">
        <h1 className="text-2xl font-bold">{currentOperation.operationName}</h1>
        <p className="mt-2 text-gray-600">{currentOperation.description}</p>
        <div className="mt-4 grid grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-gray-500">Type</p>
            <p className="font-medium">{currentOperation.type}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Status</p>
            <p className="font-medium">{currentOperation.status}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OperationDetailPage;
