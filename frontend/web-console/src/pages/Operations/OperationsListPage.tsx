import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchOperations } from '@store/slices/operationsSlice';
import { FiPlus, FiEye } from 'react-icons/fi';

const OperationsListPage: React.FC = () => {
  const dispatch = useAppDispatch();
  const { operations, loading } = useAppSelector((state) => state.operations);

  useEffect(() => {
    dispatch(fetchOperations());
  }, [dispatch]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Operations</h1>
        <button className="btn-primary flex items-center gap-2">
          <FiPlus /> New Operation
        </button>
      </div>
      <div className="card">
        {loading ? (
          <div className="flex justify-center py-12"><div className="spinner"></div></div>
        ) : (
          <div className="space-y-4">
            {operations.map((op) => (
              <div key={op.id} className="rounded-lg border p-4 flex items-center justify-between">
                <div>
                  <h3 className="font-semibold">{op.operationName}</h3>
                  <p className="text-sm text-gray-500">{op.type} - {op.status}</p>
                </div>
                <Link to={`/operations/${op.id}`} className="btn-secondary flex items-center gap-2">
                  <FiEye /> View
                </Link>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default OperationsListPage;
