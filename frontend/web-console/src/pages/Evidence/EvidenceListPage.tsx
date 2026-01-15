import React, { useEffect } from 'react';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchEvidence } from '@store/slices/evidenceSlice';
import { FiPlus, FiDownload } from 'react-icons/fi';

const EvidenceListPage: React.FC = () => {
  const dispatch = useAppDispatch();
  const { evidence, loading } = useAppSelector((state) => state.evidence);

  useEffect(() => {
    dispatch(fetchEvidence());
  }, [dispatch]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Evidence</h1>
        <button className="btn-primary flex items-center gap-2">
          <FiPlus /> Upload Evidence
        </button>
      </div>
      <div className="card">
        {loading ? (
          <div className="flex justify-center py-12"><div className="spinner"></div></div>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {evidence.map((item) => (
              <div key={item.id} className="rounded-lg border p-4">
                <h3 className="font-semibold">{item.title}</h3>
                <p className="text-sm text-gray-500">{item.type}</p>
                <button className="mt-2 flex items-center gap-1 text-sm text-primary-600">
                  <FiDownload /> Download
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default EvidenceListPage;
