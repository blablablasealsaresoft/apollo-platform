import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchOperationById } from '@store/slices/operationsSlice';
import { formatDate, formatRelativeTime } from '@utils/formatters';
import {
  FiArrowLeft,
  FiEdit,
  FiUsers,
  FiMapPin,
  FiClock,
  FiTarget,
  FiFileText,
  FiCheckCircle,
  FiAlertCircle,
  FiPlusCircle,
  FiDollarSign,
} from 'react-icons/fi';

const OperationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { currentOperation: operation, loading } = useAppSelector((state) => state.operations);
  const [activeTab, setActiveTab] = useState<'overview' | 'team' | 'timeline' | 'reports' | 'resources'>('overview');

  useEffect(() => {
    if (id) dispatch(fetchOperationById(id));
  }, [id, dispatch]);

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      planning: 'bg-gray-100 text-gray-800 dark:bg-dark-700 dark:text-gray-300',
      approved: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
      in_progress: 'bg-success-100 text-success-800 dark:bg-success-900/30 dark:text-success-300',
      completed: 'bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-300',
      cancelled: 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300',
    };
    return styles[status] || styles.planning;
  };

  const getPriorityBadge = (priority: string) => {
    const styles: Record<string, string> = {
      critical: 'bg-danger-100 text-danger-800',
      high: 'bg-warning-100 text-warning-800',
      medium: 'bg-primary-100 text-primary-800',
      low: 'bg-gray-100 text-gray-800',
    };
    return styles[priority] || styles.low;
  };

  if (loading) {
    return <div className="flex justify-center py-12"><div className="spinner" /></div>;
  }

  if (!operation) {
    return (
      <div className="text-center py-12">
        <p className="text-danger-600">Operation not found</p>
        <button onClick={() => navigate('/operations')} className="mt-4 btn-primary">Back to Operations</button>
      </div>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: FiTarget },
    { id: 'team', label: 'Team', icon: FiUsers },
    { id: 'timeline', label: 'Timeline', icon: FiClock },
    { id: 'reports', label: 'Field Reports', icon: FiFileText },
    { id: 'resources', label: 'Resources', icon: FiDollarSign },
  ] as const;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/operations" className="p-2 hover:bg-gray-100 dark:hover:bg-dark-700 rounded-lg transition-colors">
          <FiArrowLeft className="h-5 w-5" />
        </Link>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold">{operation.operationName}</h1>
            <span className={`badge ${getStatusBadge(operation.status)}`}>{operation.status.replace('_', ' ')}</span>
            <span className={`badge ${getPriorityBadge(operation.priority)}`}>{operation.priority}</span>
          </div>
          {operation.codename && <p className="text-sm text-gray-500 mt-1">Codename: {operation.codename}</p>}
        </div>
        <button className="btn-primary flex items-center gap-2"><FiEdit className="h-4 w-4" /> Edit Operation</button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-primary-100 dark:bg-primary-900/30 rounded-lg"><FiClock className="h-6 w-6 text-primary-600" /></div>
            <div>
              <p className="text-sm text-gray-500">Start Date</p>
              <p className="font-semibold">{formatDate(operation.startDate)}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-success-100 dark:bg-success-900/30 rounded-lg"><FiUsers className="h-6 w-6 text-success-600" /></div>
            <div>
              <p className="text-sm text-gray-500">Team Size</p>
              <p className="font-semibold">{operation.teamMembers?.length || 0} members</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-warning-100 dark:bg-warning-900/30 rounded-lg"><FiTarget className="h-6 w-6 text-warning-600" /></div>
            <div>
              <p className="text-sm text-gray-500">Objectives</p>
              <p className="font-semibold">{operation.objectives?.length || 0} objectives</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg"><FiDollarSign className="h-6 w-6 text-purple-600" /></div>
            <div>
              <p className="text-sm text-gray-500">Budget</p>
              <p className="font-semibold">{operation.budget ? `$${operation.budget.toLocaleString()}` : 'N/A'}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="flex border-b border-gray-200 dark:border-dark-700">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === tab.id ? 'border-primary-600 text-primary-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
          >
            <tab.icon className="h-4 w-4" />{tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Description</h3>
              <p className="text-gray-600 dark:text-gray-300 whitespace-pre-wrap">{operation.description}</p>
            </div>
            <div className="card">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Objectives</h3>
                <button className="text-sm text-primary-600 hover:underline flex items-center gap-1"><FiPlusCircle className="h-4 w-4" /> Add Objective</button>
              </div>
              {operation.objectives && operation.objectives.length > 0 ? (
                <div className="space-y-3">
                  {operation.objectives.map((objective, index) => (
                    <div key={index} className="flex items-start gap-3 p-3 bg-gray-50 dark:bg-dark-700 rounded-lg">
                      <FiCheckCircle className="h-5 w-5 text-success-600 mt-0.5" />
                      <p className="text-sm">{objective}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500 text-center py-4">No objectives defined</p>
              )}
            </div>
            {operation.riskAssessment && (
              <div className="card">
                <h3 className="text-lg font-semibold mb-4">Risk Assessment</h3>
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-sm text-gray-500">Overall Risk:</span>
                  <span className={`badge ${operation.riskAssessment.overallRisk === 'extreme' ? 'badge-danger' : operation.riskAssessment.overallRisk === 'high' ? 'badge-warning' : operation.riskAssessment.overallRisk === 'medium' ? 'badge-primary' : 'badge-gray'}`}>
                    {operation.riskAssessment.overallRisk}
                  </span>
                </div>
                {operation.riskAssessment.factors && operation.riskAssessment.factors.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Risk Factors:</p>
                    {operation.riskAssessment.factors.map((factor, index) => (
                      <div key={index} className="flex items-start gap-2 text-sm">
                        <FiAlertCircle className="h-4 w-4 text-warning-500 mt-0.5" />
                        <div><span className="font-medium">{factor.factor}</span><span className="text-gray-500"> - {factor.description}</span></div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
          <div className="space-y-6">
            {operation.location && (
              <div className="card">
                <h3 className="text-lg font-semibold mb-4">Location</h3>
                <div className="flex items-start gap-3">
                  <FiMapPin className="h-5 w-5 text-primary-600 mt-0.5" />
                  <div>
                    <p className="font-medium">{operation.location.address}</p>
                    {operation.location.description && <p className="text-sm text-gray-500 mt-1">{operation.location.description}</p>}
                    <p className="text-xs text-gray-400 mt-2">{operation.location.latitude}, {operation.location.longitude}</p>
                  </div>
                </div>
              </div>
            )}
            {operation.teamLead && (
              <div className="card">
                <h3 className="text-lg font-semibold mb-4">Team Lead</h3>
                <div className="flex items-center gap-3">
                  <div className="h-12 w-12 rounded-full bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center">
                    <span className="text-lg font-semibold text-primary-600">{operation.teamLead.firstName[0]}{operation.teamLead.lastName[0]}</span>
                  </div>
                  <div>
                    <p className="font-medium">{operation.teamLead.firstName} {operation.teamLead.lastName}</p>
                    <p className="text-sm text-gray-500">{operation.teamLead.role}</p>
                  </div>
                </div>
              </div>
            )}
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Key Dates</h3>
              <div className="space-y-3">
                <div className="flex justify-between text-sm"><span className="text-gray-500">Created</span><span>{formatDate(operation.createdAt)}</span></div>
                <div className="flex justify-between text-sm"><span className="text-gray-500">Start Date</span><span>{formatDate(operation.startDate)}</span></div>
                {operation.endDate && <div className="flex justify-between text-sm"><span className="text-gray-500">End Date</span><span>{formatDate(operation.endDate)}</span></div>}
                <div className="flex justify-between text-sm"><span className="text-gray-500">Last Updated</span><span>{formatRelativeTime(operation.updatedAt)}</span></div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'team' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Team Members</h3>
            <button className="btn-primary btn-sm flex items-center gap-1"><FiPlusCircle className="h-4 w-4" /> Add Member</button>
          </div>
          {operation.teamMembers && operation.teamMembers.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {operation.teamMembers.map((member) => (
                <div key={member.id} className="p-4 border border-gray-200 dark:border-dark-700 rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-full bg-gray-200 dark:bg-dark-700 flex items-center justify-center">
                      <span className="text-sm font-semibold">{member.firstName[0]}{member.lastName[0]}</span>
                    </div>
                    <div>
                      <p className="font-medium">{member.firstName} {member.lastName}</p>
                      <p className="text-sm text-gray-500">{member.role}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">No team members assigned</p>
          )}
        </div>
      )}

      {activeTab === 'timeline' && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Operation Timeline</h3>
          {operation.timeline && operation.timeline.length > 0 ? (
            <div className="relative">
              <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-gray-200 dark:bg-dark-700" />
              <div className="space-y-6">
                {operation.timeline.map((event) => (
                  <div key={event.id} className="flex gap-4 relative">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center z-10 ${event.importance === 'high' ? 'bg-danger-100 text-danger-600' : event.importance === 'medium' ? 'bg-warning-100 text-warning-600' : 'bg-gray-100 text-gray-600'}`}>
                      <FiClock className="h-4 w-4" />
                    </div>
                    <div className="flex-1 pb-6">
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{event.event}</p>
                        <span className="text-xs text-gray-500">{formatRelativeTime(event.timestamp)}</span>
                      </div>
                      <p className="text-sm text-gray-500 mt-1">{event.description}</p>
                      <p className="text-xs text-gray-400 mt-1">By {event.author.firstName} {event.author.lastName}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">No timeline events recorded</p>
          )}
        </div>
      )}

      {activeTab === 'reports' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Field Reports</h3>
            <button className="btn-primary btn-sm flex items-center gap-1"><FiPlusCircle className="h-4 w-4" /> New Report</button>
          </div>
          {operation.reports && operation.reports.length > 0 ? (
            <div className="space-y-4">
              {operation.reports.map((report) => (
                <div key={report.id} className="p-4 border border-gray-200 dark:border-dark-700 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="font-medium">{report.summary}</p>
                      <p className="text-sm text-gray-500 mt-1">By {report.author.firstName} {report.author.lastName} | {formatRelativeTime(report.timestamp)}</p>
                    </div>
                    <span className={`badge ${report.classification === 'top_secret' ? 'badge-danger' : report.classification === 'secret' ? 'badge-warning' : 'badge-gray'}`}>{report.classification}</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-3 line-clamp-2">{report.details}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">No field reports submitted</p>
          )}
        </div>
      )}

      {activeTab === 'resources' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Resources</h3>
            <button className="btn-primary btn-sm flex items-center gap-1"><FiPlusCircle className="h-4 w-4" /> Add Resource</button>
          </div>
          {operation.resources && operation.resources.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-dark-700">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Type</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Description</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Quantity</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Assigned To</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-dark-700">
                  {operation.resources.map((resource, index) => (
                    <tr key={index}>
                      <td className="px-4 py-3 text-sm font-medium">{resource.type}</td>
                      <td className="px-4 py-3 text-sm text-gray-500">{resource.description}</td>
                      <td className="px-4 py-3 text-sm">{resource.quantity}</td>
                      <td className="px-4 py-3 text-sm text-gray-500">{resource.assignedTo || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">No resources allocated</p>
          )}
          {(operation.budget || operation.expenditure) && (
            <div className="mt-6 pt-6 border-t border-gray-200 dark:border-dark-700">
              <h4 className="font-semibold mb-4">Budget Summary</h4>
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-gray-50 dark:bg-dark-700 rounded-lg">
                  <p className="text-sm text-gray-500">Total Budget</p>
                  <p className="text-2xl font-bold">${operation.budget?.toLocaleString() || '0'}</p>
                </div>
                <div className="p-4 bg-gray-50 dark:bg-dark-700 rounded-lg">
                  <p className="text-sm text-gray-500">Expenditure</p>
                  <p className="text-2xl font-bold">${operation.expenditure?.toLocaleString() || '0'}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default OperationDetailPage;
