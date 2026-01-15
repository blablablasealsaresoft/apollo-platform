import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { dashboardService } from '@services/api';
import { useAppSelector, useAppDispatch } from '@store/hooks';
import { fetchAlerts } from '@store/slices/alertsSlice';
import { FiFolder, FiUsers, FiFileText, FiActivity, FiAlertCircle, FiTrendingUp } from 'react-icons/fi';
import { formatRelativeTime } from '@utils/formatters';

const DashboardPage: React.FC = () => {
  const dispatch = useAppDispatch();
  const alerts = useAppSelector((state) => state.alerts.alerts);

  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const response = await dashboardService.getStats();
      return response.data;
    },
  });

  const { data: recentActivity } = useQuery({
    queryKey: ['dashboard-activity'],
    queryFn: async () => {
      const response = await dashboardService.getRecentActivity(10);
      return response.data;
    },
  });

  useEffect(() => {
    dispatch(fetchAlerts());
  }, [dispatch]);

  const statCards = [
    {
      title: 'Active Investigations',
      value: stats?.activeInvestigations || 0,
      icon: FiFolder,
      color: 'bg-primary-500',
      href: '/investigations',
    },
    {
      title: 'Total Targets',
      value: stats?.totalTargets || 0,
      icon: FiUsers,
      color: 'bg-success-500',
      href: '/targets',
    },
    {
      title: 'Active Operations',
      value: stats?.activeOperations || 0,
      icon: FiActivity,
      color: 'bg-warning-500',
      href: '/operations',
    },
    {
      title: 'Evidence Items',
      value: stats?.evidenceCount || 0,
      icon: FiFileText,
      color: 'bg-purple-500',
      href: '/evidence',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="mt-1 text-sm text-gray-500">Welcome back! Here's an overview of your operations.</p>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {statCards.map((card) => (
          <Link
            key={card.title}
            to={card.href}
            className="card hover:shadow-lg transition-shadow"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">{card.title}</p>
                <p className="mt-2 text-3xl font-bold">{card.value}</p>
              </div>
              <div className={`rounded-full p-3 ${card.color}`}>
                <card.icon className="h-6 w-6 text-white" />
              </div>
            </div>
          </Link>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Alerts */}
        <div className="card">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-semibold">Recent Alerts</h2>
            <Link to="/alerts" className="text-sm text-primary-600 hover:underline">
              View All
            </Link>
          </div>
          <div className="space-y-3">
            {alerts.slice(0, 5).map((alert) => (
              <div
                key={alert.id}
                className="flex items-start gap-3 rounded-lg border border-gray-200 p-3 dark:border-dark-700"
              >
                <FiAlertCircle className={`mt-0.5 h-5 w-5 ${
                  alert.severity === 'critical' ? 'text-danger-500' :
                  alert.severity === 'warning' ? 'text-warning-500' :
                  'text-primary-500'
                }`} />
                <div className="flex-1">
                  <p className="text-sm font-medium">{alert.title}</p>
                  <p className="text-xs text-gray-500">{formatRelativeTime(alert.createdAt)}</p>
                </div>
                <span className={`badge ${
                  alert.severity === 'critical' ? 'badge-danger' :
                  alert.severity === 'warning' ? 'badge-warning' :
                  'badge-primary'
                }`}>
                  {alert.severity}
                </span>
              </div>
            ))}
            {alerts.length === 0 && (
              <p className="text-center text-sm text-gray-500">No active alerts</p>
            )}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="card">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-semibold">Recent Activity</h2>
          </div>
          <div className="space-y-3">
            {recentActivity?.map((activity: any) => (
              <div key={activity.id} className="flex items-start gap-3">
                <div className="rounded-full bg-gray-100 p-2 dark:bg-dark-700">
                  <FiActivity className="h-4 w-4" />
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium">{activity.title}</p>
                  <p className="text-xs text-gray-500">{activity.description}</p>
                  <p className="text-xs text-gray-400">{formatRelativeTime(activity.timestamp)}</p>
                </div>
              </div>
            ))}
            {(!recentActivity || recentActivity.length === 0) && (
              <p className="text-center text-sm text-gray-500">No recent activity</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
