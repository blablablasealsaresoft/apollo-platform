import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchInvestigations } from '@store/slices/investigationsSlice';
import { FiPlus, FiSearch, FiEye } from 'react-icons/fi';
import { formatDate } from '@utils/formatters';

const InvestigationsListPage: React.FC = () => {
  const dispatch = useAppDispatch();
  const { investigations, loading } = useAppSelector((state) => state.investigations);

  useEffect(() => {
    dispatch(fetchInvestigations());
  }, [dispatch]);

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'badge-danger';
      case 'high': return 'badge-warning';
      case 'medium': return 'badge-primary';
      default: return 'badge-gray';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'badge-success';
      case 'planning': return 'badge-primary';
      case 'on_hold': return 'badge-warning';
      case 'closed': return 'badge-gray';
      default: return 'badge-gray';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Investigations</h1>
          <p className="mt-1 text-sm text-gray-500">Manage all active and archived investigations</p>
        </div>
        <Link to="/investigations/new" className="btn-primary flex items-center gap-2">
          <FiPlus className="h-5 w-5" />
          New Investigation
        </Link>
      </div>

      <div className="card">
        <div className="mb-4 flex items-center gap-4">
          <div className="relative flex-1">
            <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search investigations..."
              className="input pl-10"
            />
          </div>
          <select className="input w-48">
            <option>All Statuses</option>
            <option>Active</option>
            <option>Planning</option>
            <option>On Hold</option>
            <option>Closed</option>
          </select>
          <select className="input w-48">
            <option>All Priorities</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="spinner"></div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Case Number</th>
                  <th>Title</th>
                  <th>Status</th>
                  <th>Priority</th>
                  <th>Lead Investigator</th>
                  <th>Targets</th>
                  <th>Start Date</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {investigations.map((inv) => (
                  <tr key={inv.id}>
                    <td className="font-mono text-sm">{inv.caseNumber}</td>
                    <td className="font-medium">{inv.title}</td>
                    <td>
                      <span className={`badge ${getStatusColor(inv.status)}`}>
                        {inv.status}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${getPriorityColor(inv.priority)}`}>
                        {inv.priority}
                      </span>
                    </td>
                    <td>
                      {inv.leadInvestigator.firstName} {inv.leadInvestigator.lastName}
                    </td>
                    <td>{inv.targets?.length || 0}</td>
                    <td>{formatDate(inv.startDate)}</td>
                    <td>
                      <Link
                        to={`/investigations/${inv.id}`}
                        className="inline-flex items-center gap-1 text-primary-600 hover:underline"
                      >
                        <FiEye className="h-4 w-4" />
                        View
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {investigations.length === 0 && (
              <div className="py-12 text-center">
                <p className="text-gray-500">No investigations found</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default InvestigationsListPage;
