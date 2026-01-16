import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { dashboardService } from '@services/api';
import { useAppSelector, useAppDispatch } from '@store/hooks';
import { fetchAlerts } from '@store/slices/alertsSlice';
import {
  FiFolder,
  FiUsers,
  FiFileText,
  FiActivity,
  FiAlertCircle,
  FiTrendingUp,
  FiPlus,
  FiSearch,
  FiMap,
  FiEye,
  FiTarget,
  FiCpu,
  FiGlobe,
  FiClock,
  FiArrowRight,
  FiCheckCircle,
  FiXCircle,
  FiRefreshCw,
} from 'react-icons/fi';
import { formatRelativeTime } from '@utils/formatters';
import { Card, CardHeader, Button, Badge } from '@components/common/UI';
import { Spinner } from '@components/common/Loading';
import { ProgressBar } from '@components/common/UI/ProgressBar';

const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const alerts = useAppSelector((state) => state.alerts.alerts);
  const alertsLoading = useAppSelector((state) => state.alerts.loading);
  const [refreshing, setRefreshing] = useState(false);

  const { data: stats, isLoading, refetch: refetchStats } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const response = await dashboardService.getStats();
      return response.data;
    },
    refetchInterval: 60000, // Refresh every minute
  });

  const { data: recentActivity, refetch: refetchActivity } = useQuery({
    queryKey: ['dashboard-activity'],
    queryFn: async () => {
      const response = await dashboardService.getRecentActivity(10);
      return response.data;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Mock high-priority targets for watch list
  const { data: watchlistTargets } = useQuery({
    queryKey: ['dashboard-watchlist'],
    queryFn: async () => {
      // This would be a real API call
      await new Promise(resolve => setTimeout(resolve, 300));
      return [
        {
          id: '1',
          name: 'Ruja Ignatova',
          alias: 'Cryptoqueen',
          riskLevel: 'extreme',
          lastSeen: '2024-12-15T10:30:00Z',
          location: 'Unknown',
          photo: null,
        },
        {
          id: '2',
          name: 'Mark Scott',
          alias: 'Lawyer',
          riskLevel: 'high',
          lastSeen: '2024-12-18T14:22:00Z',
          location: 'New York, USA',
          photo: null,
        },
        {
          id: '3',
          name: 'Sebastian Greenwood',
          alias: 'Co-founder',
          riskLevel: 'high',
          lastSeen: '2024-12-20T08:45:00Z',
          location: 'Thailand',
          photo: null,
        },
      ];
    },
  });

  // Mock active operations
  const { data: activeOperations } = useQuery({
    queryKey: ['dashboard-operations'],
    queryFn: async () => {
      await new Promise(resolve => setTimeout(resolve, 200));
      return [
        {
          id: '1',
          name: 'Operation Phoenix',
          status: 'in_progress',
          progress: 65,
          teamLead: 'Agent Smith',
          dueDate: '2025-01-25',
        },
        {
          id: '2',
          name: 'Operation Cryptotrack',
          status: 'in_progress',
          progress: 45,
          teamLead: 'Agent Johnson',
          dueDate: '2025-02-10',
        },
        {
          id: '3',
          name: 'Operation Darkweb',
          status: 'planning',
          progress: 15,
          teamLead: 'Agent Williams',
          dueDate: '2025-03-01',
        },
      ];
    },
  });

  useEffect(() => {
    dispatch(fetchAlerts());
  }, [dispatch]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([
      refetchStats(),
      refetchActivity(),
      dispatch(fetchAlerts()),
    ]);
    setRefreshing(false);
  };

  const statCards = [
    {
      title: 'Active Investigations',
      value: stats?.activeInvestigations || 0,
      icon: FiFolder,
      color: 'bg-primary-500',
      href: '/investigations',
      change: '+3 this week',
    },
    {
      title: 'Total Targets',
      value: stats?.totalTargets || 0,
      icon: FiUsers,
      color: 'bg-success-500',
      href: '/targets',
      change: '+5 this month',
    },
    {
      title: 'Active Operations',
      value: stats?.activeOperations || 0,
      icon: FiActivity,
      color: 'bg-warning-500',
      href: '/operations',
      change: '2 in progress',
    },
    {
      title: 'Evidence Items',
      value: stats?.evidenceCount || 0,
      icon: FiFileText,
      color: 'bg-purple-500',
      href: '/evidence',
      change: '+12 this week',
    },
  ];

  const quickActions = [
    {
      icon: FiPlus,
      label: 'New Investigation',
      onClick: () => navigate('/investigations/new'),
      color: 'bg-primary-50 text-primary-600 dark:bg-primary-900/20 dark:text-primary-400',
    },
    {
      icon: FiSearch,
      label: 'Search Targets',
      onClick: () => navigate('/targets?search=true'),
      color: 'bg-success-50 text-success-600 dark:bg-success-900/20 dark:text-success-400',
    },
    {
      icon: FiMap,
      label: 'Geolocation',
      onClick: () => navigate('/geolocation'),
      color: 'bg-warning-50 text-warning-600 dark:bg-warning-900/20 dark:text-warning-400',
    },
    {
      icon: FiEye,
      label: 'Facial Recognition',
      onClick: () => navigate('/facial-recognition'),
      color: 'bg-purple-50 text-purple-600 dark:bg-purple-900/20 dark:text-purple-400',
    },
    {
      icon: FiGlobe,
      label: 'Blockchain Analysis',
      onClick: () => navigate('/blockchain'),
      color: 'bg-blue-50 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400',
    },
    {
      icon: FiCpu,
      label: 'Intelligence Hub',
      onClick: () => navigate('/intelligence'),
      color: 'bg-indigo-50 text-indigo-600 dark:bg-indigo-900/20 dark:text-indigo-400',
    },
  ];

  const getRiskBadgeVariant = (risk: string) => {
    switch (risk) {
      case 'extreme': return 'danger';
      case 'high': return 'warning';
      case 'medium': return 'primary';
      default: return 'default';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Spinner size="xl" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Welcome back! Here's an overview of your operations.
          </p>
        </div>
        <Button
          variant="outline"
          onClick={handleRefresh}
          loading={refreshing}
          leftIcon={<FiRefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />}
        >
          Refresh
        </Button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {statCards.map((card) => (
          <Link
            key={card.title}
            to={card.href}
            className="card hover:shadow-lg transition-all hover:-translate-y-1"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">{card.title}</p>
                <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">{card.value}</p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{card.change}</p>
              </div>
              <div className={`rounded-full p-3 ${card.color}`}>
                <card.icon className="h-6 w-6 text-white" />
              </div>
            </div>
          </Link>
        ))}
      </div>

      {/* Quick Actions */}
      <Card padding="md">
        <CardHeader
          title="Quick Actions"
          description="Frequently used tools and shortcuts"
        />
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {quickActions.map((action) => (
            <button
              key={action.label}
              onClick={action.onClick}
              className={`flex flex-col items-center gap-2 p-4 rounded-lg transition-all hover:shadow-md ${action.color}`}
            >
              <action.icon className="h-6 w-6" />
              <span className="text-sm font-medium text-center">{action.label}</span>
            </button>
          ))}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Recent Alerts */}
        <Card padding="md" className="lg:col-span-1">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Alerts</h2>
            <Link to="/alerts" className="text-sm text-primary-600 hover:underline flex items-center gap-1">
              View All <FiArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="space-y-3">
            {alertsLoading ? (
              <div className="flex justify-center py-8">
                <Spinner />
              </div>
            ) : alerts.length === 0 ? (
              <div className="text-center py-8">
                <FiCheckCircle className="h-12 w-12 mx-auto text-success-500 mb-2" />
                <p className="text-sm text-gray-500 dark:text-gray-400">No active alerts</p>
              </div>
            ) : (
              alerts.slice(0, 5).map((alert) => (
                <div
                  key={alert.id}
                  className="flex items-start gap-3 p-3 rounded-lg border border-gray-200 dark:border-dark-700 hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors cursor-pointer"
                >
                  <FiAlertCircle className={`mt-0.5 h-5 w-5 flex-shrink-0 ${
                    alert.severity === 'critical' ? 'text-danger-500' :
                    alert.severity === 'warning' ? 'text-warning-500' :
                    'text-primary-500'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{alert.title}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{formatRelativeTime(alert.createdAt)}</p>
                  </div>
                  <Badge
                    variant={
                      alert.severity === 'critical' ? 'danger' :
                      alert.severity === 'warning' ? 'warning' : 'primary'
                    }
                    size="sm"
                  >
                    {alert.severity}
                  </Badge>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Target Watch List */}
        <Card padding="md" className="lg:col-span-1">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Target Watch List</h2>
            <Link to="/targets?priority=high" className="text-sm text-primary-600 hover:underline flex items-center gap-1">
              View All <FiArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="space-y-3">
            {watchlistTargets?.map((target: any) => (
              <Link
                key={target.id}
                to={`/targets/${target.id}`}
                className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 dark:border-dark-700 hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
              >
                <div className="h-10 w-10 rounded-full bg-gray-200 dark:bg-dark-700 flex items-center justify-center flex-shrink-0">
                  <FiTarget className="h-5 w-5 text-gray-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{target.name}</p>
                  <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                    <FiClock className="h-3 w-3" />
                    <span className="truncate">Last seen: {formatRelativeTime(target.lastSeen)}</span>
                  </div>
                </div>
                <Badge variant={getRiskBadgeVariant(target.riskLevel)} size="sm">
                  {target.riskLevel}
                </Badge>
              </Link>
            ))}
            {(!watchlistTargets || watchlistTargets.length === 0) && (
              <div className="text-center py-8">
                <FiTarget className="h-12 w-12 mx-auto text-gray-400 mb-2" />
                <p className="text-sm text-gray-500 dark:text-gray-400">No targets in watch list</p>
              </div>
            )}
          </div>
        </Card>

        {/* Active Operations */}
        <Card padding="md" className="lg:col-span-1">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Active Operations</h2>
            <Link to="/operations" className="text-sm text-primary-600 hover:underline flex items-center gap-1">
              View All <FiArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="space-y-4">
            {activeOperations?.map((op: any) => (
              <Link
                key={op.id}
                to={`/operations/${op.id}`}
                className="block p-3 rounded-lg border border-gray-200 dark:border-dark-700 hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
              >
                <div className="flex items-center justify-between mb-2">
                  <p className="text-sm font-medium text-gray-900 dark:text-white">{op.name}</p>
                  <Badge
                    variant={op.status === 'in_progress' ? 'success' : 'default'}
                    size="sm"
                  >
                    {op.status.replace('_', ' ')}
                  </Badge>
                </div>
                <ProgressBar value={op.progress} size="sm" variant="primary" />
                <div className="flex items-center justify-between mt-2 text-xs text-gray-500 dark:text-gray-400">
                  <span>{op.teamLead}</span>
                  <span>Due: {op.dueDate}</span>
                </div>
              </Link>
            ))}
            {(!activeOperations || activeOperations.length === 0) && (
              <div className="text-center py-8">
                <FiActivity className="h-12 w-12 mx-auto text-gray-400 mb-2" />
                <p className="text-sm text-gray-500 dark:text-gray-400">No active operations</p>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Recent Activity - Full Width */}
      <Card padding="md">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Activity</h2>
        </div>
        <div className="relative">
          {/* Timeline line */}
          <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-gray-200 dark:bg-dark-700" />

          <div className="space-y-4">
            {recentActivity?.map((activity: any, index: number) => (
              <div key={activity.id} className="relative flex items-start gap-4 pl-10">
                {/* Timeline dot */}
                <div className="absolute left-2.5 w-3 h-3 rounded-full bg-primary-500 ring-4 ring-white dark:ring-dark-800" />

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">{activity.title}</p>
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {formatRelativeTime(activity.timestamp)}
                    </span>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{activity.description}</p>
                </div>
              </div>
            ))}
            {(!recentActivity || recentActivity.length === 0) && (
              <div className="text-center py-8">
                <FiClock className="h-12 w-12 mx-auto text-gray-400 mb-2" />
                <p className="text-sm text-gray-500 dark:text-gray-400">No recent activity</p>
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* System Status */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card padding="sm">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-success-100 p-2 dark:bg-success-900/30">
              <FiCheckCircle className="h-5 w-5 text-success-600 dark:text-success-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">API Status</p>
              <p className="font-semibold text-success-600 dark:text-success-400">Operational</p>
            </div>
          </div>
        </Card>
        <Card padding="sm">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-success-100 p-2 dark:bg-success-900/30">
              <FiCheckCircle className="h-5 w-5 text-success-600 dark:text-success-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Database</p>
              <p className="font-semibold text-success-600 dark:text-success-400">Connected</p>
            </div>
          </div>
        </Card>
        <Card padding="sm">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-success-100 p-2 dark:bg-success-900/30">
              <FiCheckCircle className="h-5 w-5 text-success-600 dark:text-success-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">WebSocket</p>
              <p className="font-semibold text-success-600 dark:text-success-400">Real-time Active</p>
            </div>
          </div>
        </Card>
        <Card padding="sm">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-primary-100 p-2 dark:bg-primary-900/30">
              <FiTrendingUp className="h-5 w-5 text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">System Load</p>
              <p className="font-semibold text-gray-900 dark:text-white">24% CPU</p>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default DashboardPage;
