import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchTargetById } from '@store/slices/targetsSlice';
import { formatDate, formatRelativeTime } from '@utils/formatters';
import {
  FiArrowLeft,
  FiEdit,
  FiMapPin,
  FiPhone,
  FiMail,
  FiGlobe,
  FiUsers,
  FiAlertTriangle,
  FiDollarSign,
  FiClock,
  FiCamera,
  FiActivity,
} from 'react-icons/fi';

const TargetDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { currentTarget: target, loading } = useAppSelector((state) => state.targets);
  const [activeTab, setActiveTab] = useState<'overview' | 'associates' | 'financial' | 'locations' | 'timeline'>('overview');

  useEffect(() => {
    if (id) dispatch(fetchTargetById(id));
  }, [id, dispatch]);

  const getRiskBadge = (risk: string) => {
    const styles: Record<string, string> = {
      extreme: 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300',
      high: 'bg-warning-100 text-warning-800 dark:bg-warning-900/30 dark:text-warning-300',
      medium: 'bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-300',
      low: 'bg-gray-100 text-gray-800 dark:bg-dark-700 dark:text-gray-300',
    };
    return styles[risk] || styles.low;
  };

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      active: 'bg-danger-100 text-danger-800',
      monitoring: 'bg-warning-100 text-warning-800',
      apprehended: 'bg-success-100 text-success-800',
      cleared: 'bg-gray-100 text-gray-800',
      deceased: 'bg-gray-500 text-white',
    };
    return styles[status] || styles.active;
  };

  if (loading) {
    return <div className="flex justify-center py-12"><div className="spinner" /></div>;
  }

  if (!target) {
    return (
      <div className="text-center py-12">
        <p className="text-danger-600">Target not found</p>
        <button onClick={() => navigate('/targets')} className="mt-4 btn-primary">Back to Targets</button>
      </div>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: FiActivity },
    { id: 'associates', label: 'Associates', icon: FiUsers },
    { id: 'financial', label: 'Financial', icon: FiDollarSign },
    { id: 'locations', label: 'Locations', icon: FiMapPin },
    { id: 'timeline', label: 'Timeline', icon: FiClock },
  ] as const;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/targets" className="p-2 hover:bg-gray-100 dark:hover:bg-dark-700 rounded-lg transition-colors">
          <FiArrowLeft className="h-5 w-5" />
        </Link>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold">{target.firstName} {target.lastName}</h1>
            <span className={`badge ${getRiskBadge(target.riskLevel)}`}>{target.riskLevel} risk</span>
            <span className={`badge ${getStatusBadge(target.status)}`}>{target.status}</span>
          </div>
          {target.aliases && target.aliases.length > 0 && (
            <p className="text-sm text-gray-500 mt-1">Also known as: {target.aliases.join(', ')}</p>
          )}
        </div>
        <button className="btn-primary flex items-center gap-2"><FiEdit className="h-4 w-4" /> Edit Target</button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <div className="card">
            <div className="flex flex-col items-center text-center">
              <div className="h-32 w-32 rounded-full bg-gray-200 dark:bg-dark-700 flex items-center justify-center text-4xl font-bold mb-4">
                {target.photo ? (
                  <img src={target.photo} alt={target.firstName} className="h-full w-full rounded-full object-cover" />
                ) : (
                  `${target.firstName[0]}${target.lastName[0]}`
                )}
              </div>
              <h2 className="text-xl font-semibold">{target.firstName} {target.lastName}</h2>
              {target.nationality && <p className="text-sm text-gray-500 mt-1">{target.nationality}</p>}
              {target.dateOfBirth && <p className="text-sm text-gray-500">DOB: {formatDate(target.dateOfBirth)}</p>}
            </div>

            <div className="mt-6 space-y-4 border-t border-gray-200 dark:border-dark-700 pt-6">
              {target.phoneNumbers && target.phoneNumbers.length > 0 && (
                <div className="flex items-start gap-3">
                  <FiPhone className="h-5 w-5 text-gray-400 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium">Phone Numbers</p>
                    {target.phoneNumbers.map((phone, i) => <p key={i} className="text-sm text-gray-500">{phone}</p>)}
                  </div>
                </div>
              )}
              {target.emailAddresses && target.emailAddresses.length > 0 && (
                <div className="flex items-start gap-3">
                  <FiMail className="h-5 w-5 text-gray-400 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium">Email Addresses</p>
                    {target.emailAddresses.map((email, i) => <p key={i} className="text-sm text-gray-500">{email}</p>)}
                  </div>
                </div>
              )}
              {target.socialMedia && target.socialMedia.length > 0 && (
                <div className="flex items-start gap-3">
                  <FiGlobe className="h-5 w-5 text-gray-400 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium">Social Media</p>
                    {target.socialMedia.map((account, i) => <p key={i} className="text-sm text-gray-500">{account.platform}: @{account.username}</p>)}
                  </div>
                </div>
              )}
            </div>

            <div className="mt-6 flex gap-2">
              <button className="btn-secondary flex-1 flex items-center justify-center gap-2"><FiCamera className="h-4 w-4" /> Facial Search</button>
              <button className="btn-secondary flex-1 flex items-center justify-center gap-2"><FiAlertTriangle className="h-4 w-4" /> Create Alert</button>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 space-y-6">
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
            <div className="space-y-6">
              <div className="card">
                <h3 className="text-lg font-semibold mb-4">Criminal History</h3>
                {target.criminalHistory && target.criminalHistory.length > 0 ? (
                  <div className="space-y-3">
                    {target.criminalHistory.map((record) => (
                      <div key={record.id} className="p-3 bg-gray-50 dark:bg-dark-700 rounded-lg">
                        <div className="flex justify-between">
                          <p className="font-medium">{record.offense}</p>
                          <p className="text-sm text-gray-500">{formatDate(record.date)}</p>
                        </div>
                        <p className="text-sm text-gray-500">{record.jurisdiction} - {record.disposition}</p>
                        {record.sentence && <p className="text-sm text-danger-600 mt-1">Sentence: {record.sentence}</p>}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500 text-center py-4">No criminal history on record</p>
                )}
              </div>
              <div className="card">
                <h3 className="text-lg font-semibold mb-4">Notes</h3>
                <p className="text-gray-600 dark:text-gray-300 whitespace-pre-wrap">{target.notes || 'No notes available'}</p>
              </div>
            </div>
          )}

          {activeTab === 'associates' && (
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Known Associates</h3>
              {target.knownAssociates && target.knownAssociates.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {target.knownAssociates.map((associate) => (
                    <div key={associate.targetId} className="p-4 border border-gray-200 dark:border-dark-700 rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className="h-10 w-10 rounded-full bg-gray-200 dark:bg-dark-700 flex items-center justify-center"><FiUsers className="h-5 w-5 text-gray-500" /></div>
                        <div>
                          <p className="font-medium">{associate.name}</p>
                          <p className="text-sm text-gray-500">{associate.relationship}</p>
                        </div>
                      </div>
                      <div className="mt-3 flex items-center justify-between text-sm">
                        <span className="text-gray-500">Confidence: {Math.round(associate.confidence * 100)}%</span>
                        {associate.lastContact && <span className="text-gray-500">Last contact: {formatRelativeTime(associate.lastContact)}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500 text-center py-4">No known associates</p>
              )}
            </div>
          )}

          {activeTab === 'financial' && (
            <div className="space-y-6">
              {target.financialProfile ? (
                <>
                  <div className="card">
                    <h3 className="text-lg font-semibold mb-4">Cryptocurrency Wallets</h3>
                    {target.financialProfile.cryptocurrencyWallets?.length > 0 ? (
                      <div className="space-y-3">
                        {target.financialProfile.cryptocurrencyWallets.map((wallet) => (
                          <div key={wallet.id} className="p-3 bg-gray-50 dark:bg-dark-700 rounded-lg">
                            <div className="flex justify-between items-start">
                              <div>
                                <p className="font-mono text-sm">{wallet.address}</p>
                                <p className="text-sm text-gray-500">{wallet.blockchain} - {wallet.transactionCount} transactions</p>
                              </div>
                              {wallet.balance !== undefined && <p className="font-semibold">{wallet.balance} {wallet.currency}</p>}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-500 text-center py-4">No cryptocurrency wallets on record</p>
                    )}
                  </div>
                  <div className="card">
                    <h3 className="text-lg font-semibold mb-4">Suspicious Transactions</h3>
                    {target.financialProfile.suspiciousTransactions?.length > 0 ? (
                      <div className="space-y-3">
                        {target.financialProfile.suspiciousTransactions.map((tx) => (
                          <div key={tx.id} className="p-3 bg-danger-50 dark:bg-danger-900/20 rounded-lg border border-danger-200 dark:border-danger-800">
                            <div className="flex justify-between">
                              <p className="font-medium text-danger-800 dark:text-danger-300">{tx.amount} {tx.currency}</p>
                              <p className="text-sm text-gray-500">{formatDate(tx.date)}</p>
                            </div>
                            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{tx.from} → {tx.to}</p>
                            <div className="mt-2 flex flex-wrap gap-1">
                              {tx.flags.map((flag, i) => <span key={i} className="text-xs px-2 py-0.5 bg-danger-100 dark:bg-danger-900/30 text-danger-700 dark:text-danger-300 rounded">{flag}</span>)}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-500 text-center py-4">No suspicious transactions flagged</p>
                    )}
                  </div>
                </>
              ) : (
                <div className="card"><p className="text-gray-500 text-center py-8">No financial profile available</p></div>
              )}
            </div>
          )}

          {activeTab === 'locations' && (
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Location History</h3>
              {target.locationHistory && target.locationHistory.length > 0 ? (
                <div className="space-y-3">
                  {target.locationHistory.map((location) => (
                    <div key={location.id} className="flex items-start gap-3 p-3 bg-gray-50 dark:bg-dark-700 rounded-lg">
                      <FiMapPin className="h-5 w-5 text-primary-600 mt-0.5" />
                      <div className="flex-1">
                        <p className="font-medium">{location.address || `${location.latitude}, ${location.longitude}`}</p>
                        <p className="text-sm text-gray-500">Source: {location.source} | {formatRelativeTime(location.timestamp)}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500 text-center py-4">No location history available</p>
              )}
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Activity Timeline</h3>
              <p className="text-gray-500 text-center py-8">Timeline view coming soon</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TargetDetailPage;
