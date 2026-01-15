import React, { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchTargetById } from '@store/slices/targetsSlice';

const TargetDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const dispatch = useAppDispatch();
  const { currentTarget, loading } = useAppSelector((state) => state.targets);

  useEffect(() => {
    if (id) dispatch(fetchTargetById(id));
  }, [id, dispatch]);

  if (loading) return <div className="flex justify-center py-12"><div className="spinner"></div></div>;
  if (!currentTarget) return <div>Target not found</div>;

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="flex items-start gap-6">
          <div className="h-32 w-32 rounded-full bg-gray-200 flex items-center justify-center text-4xl font-bold">
            {currentTarget.firstName[0]}{currentTarget.lastName[0]}
          </div>
          <div className="flex-1">
            <h1 className="text-3xl font-bold">{currentTarget.firstName} {currentTarget.lastName}</h1>
            {currentTarget.aliases?.length > 0 && (
              <p className="text-gray-500">Aliases: {currentTarget.aliases.join(', ')}</p>
            )}
            <div className="mt-4 grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-500">Risk Level</p>
                <p className="font-medium">{currentTarget.riskLevel}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Status</p>
                <p className="font-medium">{currentTarget.status}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Nationality</p>
                <p>{currentTarget.nationality || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Date of Birth</p>
                <p>{currentTarget.dateOfBirth || 'Unknown'}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TargetDetailPage;
