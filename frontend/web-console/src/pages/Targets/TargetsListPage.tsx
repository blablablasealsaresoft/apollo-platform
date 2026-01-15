import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchTargets } from '@store/slices/targetsSlice';
import { FiPlus, FiSearch, FiEye } from 'react-icons/fi';

const TargetsListPage: React.FC = () => {
  const dispatch = useAppDispatch();
  const { targets, loading } = useAppSelector((state) => state.targets);

  useEffect(() => {
    dispatch(fetchTargets());
  }, [dispatch]);

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'extreme': return 'badge-danger';
      case 'high': return 'badge-warning';
      case 'medium': return 'badge-primary';
      default: return 'badge-gray';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Targets</h1>
        <Link to="/targets/new" className="btn-primary flex items-center gap-2">
          <FiPlus /> New Target
        </Link>
      </div>

      <div className="card">
        <div className="mb-4">
          <div className="relative">
            <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input type="text" placeholder="Search targets..." className="input pl-10" />
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center py-12"><div className="spinner"></div></div>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {targets.map((target) => (
              <div key={target.id} className="rounded-lg border border-gray-200 p-4 hover:shadow-lg transition-shadow dark:border-dark-700">
                <div className="flex items-start gap-4">
                  <div className="h-16 w-16 rounded-full bg-gray-200 flex items-center justify-center text-2xl font-bold">
                    {target.firstName[0]}{target.lastName[0]}
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold">{target.firstName} {target.lastName}</h3>
                    {target.aliases?.length > 0 && (
                      <p className="text-xs text-gray-500">aka {target.aliases[0]}</p>
                    )}
                    <div className="mt-2 flex items-center gap-2">
                      <span className={`badge ${getRiskColor(target.riskLevel)}`}>
                        {target.riskLevel}
                      </span>
                      <span className="badge badge-gray">{target.status}</span>
                    </div>
                    <Link to={`/targets/${target.id}`} className="mt-2 inline-flex items-center gap-1 text-sm text-primary-600 hover:underline">
                      <FiEye className="h-4 w-4" /> View Profile
                    </Link>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default TargetsListPage;
