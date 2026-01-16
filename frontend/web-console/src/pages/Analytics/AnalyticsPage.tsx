import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  ZAxis,
} from 'recharts';
import { FiTrendingUp, FiActivity, FiTarget, FiFileText, FiDownload, FiCalendar, FiFilter, FiRefreshCw } from 'react-icons/fi';
import { Card, CardHeader } from '@components/common/UI';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@components/common/UI/Tabs';
import { StatCard } from '@components/common/UI/StatCard';
import { PageLoader } from '@components/common/Loading';
import { Button } from '@components/common/UI/Button';
import { Select } from '@components/common/Forms';
import { analyticsService } from '@services/api';
import toast from 'react-hot-toast';

const COLORS = ['#6366f1', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'];

const AnalyticsPage: React.FC = () => {
  const [dateRange, setDateRange] = useState('30d');
  const [activeTab, setActiveTab] = useState('overview');
  const [exporting, setExporting] = useState(false);

  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['analytics-stats', dateRange],
    queryFn: async () => {
      const response = await analyticsService.getOverviewStats(dateRange);
      return response;
    },
  });

  const { data: trends, refetch: refetchTrends } = useQuery({
    queryKey: ['investigation-trends', dateRange],
    queryFn: async () => {
      const response = await analyticsService.getInvestigationTrends(dateRange);
      return response;
    },
  });

  const { data: alertTypes, refetch: refetchAlertTypes } = useQuery({
    queryKey: ['alert-types'],
    queryFn: async () => {
      const response = await analyticsService.getAlertsByType();
      return response;
    },
  });

  const { data: riskDistribution, refetch: refetchRiskDistribution } = useQuery({
    queryKey: ['risk-distribution'],
    queryFn: async () => {
      const response = await analyticsService.getTargetRiskDistribution();
      return response;
    },
  });

  const { data: activityData, refetch: refetchActivity } = useQuery({
    queryKey: ['activity-by-hour'],
    queryFn: async () => {
      const response = await analyticsService.getActivityByHour();
      return response;
    },
  });

  const { data: geoData, refetch: refetchGeo } = useQuery({
    queryKey: ['geo-distribution'],
    queryFn: async () => {
      const response = await analyticsService.getGeographicDistribution();
      return response;
    },
  });

  const { data: evidenceData, refetch: refetchEvidence } = useQuery({
    queryKey: ['evidence-by-type'],
    queryFn: async () => {
      const response = await analyticsService.getEvidenceByType();
      return response;
    },
  });

  const handleRefresh = async () => {
    await Promise.all([
      refetchStats(),
      refetchTrends(),
      refetchAlertTypes(),
      refetchRiskDistribution(),
      refetchActivity(),
      refetchGeo(),
      refetchEvidence(),
    ]);
    toast.success('Analytics data refreshed');
  };

  const handleExport = async (format: 'pdf' | 'csv' | 'excel') => {
    setExporting(true);
    try {
      await analyticsService.exportAnalytics(format, dateRange);
      toast.success(`Analytics exported as ${format.toUpperCase()}`);
    } catch (error) {
      toast.error('Failed to export analytics');
    } finally {
      setExporting(false);
    }
  };

  if (statsLoading) {
    return <PageLoader message="Loading analytics..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Analytics & Reports
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Comprehensive insights and performance metrics
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Select
            value={dateRange}
            onChange={(e) => setDateRange(e.target.value)}
            className="w-40"
          >
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="1y">Last year</option>
          </Select>
          <Button
            variant="outline"
            size="sm"
            leftIcon={<FiRefreshCw className="h-4 w-4" />}
            onClick={handleRefresh}
          >
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            leftIcon={<FiDownload className="h-4 w-4" />}
            onClick={() => handleExport('pdf')}
            loading={exporting}
          >
            Export PDF
          </Button>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Investigations"
          value={stats?.data?.totalInvestigations || 0}
          change={stats?.data?.investigationChange}
          trend={stats?.data?.investigationChange > 0 ? 'up' : 'down'}
          changeLabel="vs last period"
          icon={<FiTrendingUp />}
          iconColor="bg-primary-500"
        />
        <StatCard
          title="Active Targets"
          value={stats?.data?.activeTargets || 0}
          change={stats?.data?.targetChange}
          trend={stats?.data?.targetChange > 0 ? 'up' : 'down'}
          changeLabel="vs last period"
          icon={<FiTarget />}
          iconColor="bg-success-500"
        />
        <StatCard
          title="Alerts Resolved"
          value={stats?.data?.alertsResolved || 0}
          change={stats?.data?.alertChange}
          trend={stats?.data?.alertChange > 0 ? 'up' : 'down'}
          changeLabel="vs last period"
          icon={<FiActivity />}
          iconColor="bg-warning-500"
        />
        <StatCard
          title="Evidence Collected"
          value={stats?.data?.evidenceCollected || 0}
          change={stats?.data?.evidenceChange}
          trend={stats?.data?.evidenceChange > 0 ? 'up' : 'down'}
          changeLabel="vs last period"
          icon={<FiFileText />}
          iconColor="bg-purple-500"
        />
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="investigations">Investigations</TabsTrigger>
          <TabsTrigger value="targets">Targets</TabsTrigger>
          <TabsTrigger value="operations">Operations</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Investigation Trends */}
            <Card padding="md">
              <CardHeader
                title="Investigation Trends"
                description="Monthly investigation activity over the past year"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trends?.data || []}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                    <XAxis
                      dataKey="month"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <YAxis
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                    />
                    <Legend />
                    <Area
                      type="monotone"
                      dataKey="active"
                      stackId="1"
                      stroke="#6366f1"
                      fill="#6366f1"
                      fillOpacity={0.3}
                      name="Active"
                    />
                    <Area
                      type="monotone"
                      dataKey="opened"
                      stackId="2"
                      stroke="#22c55e"
                      fill="#22c55e"
                      fillOpacity={0.3}
                      name="Opened"
                    />
                    <Area
                      type="monotone"
                      dataKey="closed"
                      stackId="3"
                      stroke="#f59e0b"
                      fill="#f59e0b"
                      fillOpacity={0.3}
                      name="Closed"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Alerts by Type */}
            <Card padding="md">
              <CardHeader
                title="Alerts by Type"
                description="Distribution of alerts across categories"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={alertTypes?.data || []}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {(alertTypes?.data || []).map((entry: any, index: number) => (
                        <Cell key={`cell-${index}`} fill={entry.color || COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Activity by Hour */}
            <Card padding="md">
              <CardHeader
                title="Activity by Hour"
                description="System activity patterns throughout the day"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={activityData?.data || []}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                    <XAxis
                      dataKey="hour"
                      tick={{ fill: '#9ca3af', fontSize: 10 }}
                      axisLine={{ stroke: '#374151' }}
                      interval={3}
                    />
                    <YAxis
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                    />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="alerts"
                      stroke="#ef4444"
                      strokeWidth={2}
                      dot={false}
                      name="Alerts"
                    />
                    <Line
                      type="monotone"
                      dataKey="logins"
                      stroke="#6366f1"
                      strokeWidth={2}
                      dot={false}
                      name="Logins"
                    />
                    <Line
                      type="monotone"
                      dataKey="searches"
                      stroke="#22c55e"
                      strokeWidth={2}
                      dot={false}
                      name="Searches"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Geographic Distribution */}
            <Card padding="md">
              <CardHeader
                title="Geographic Distribution"
                description="Targets and operations by region"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={geoData?.data || []} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                    <XAxis
                      type="number"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <YAxis
                      dataKey="region"
                      type="category"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                      width={100}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                    />
                    <Legend />
                    <Bar dataKey="targets" fill="#6366f1" name="Targets" radius={[0, 4, 4, 0]} />
                    <Bar dataKey="operations" fill="#22c55e" name="Operations" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="investigations">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Investigation Status */}
            <Card padding="md">
              <CardHeader
                title="Investigation Status"
                description="Current status distribution"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Active', value: 45, color: '#22c55e' },
                        { name: 'Planning', value: 18, color: '#6366f1' },
                        { name: 'On Hold', value: 12, color: '#f59e0b' },
                        { name: 'Closed', value: 35, color: '#9ca3af' },
                      ]}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {[
                        { color: '#22c55e' },
                        { color: '#6366f1' },
                        { color: '#f59e0b' },
                        { color: '#9ca3af' },
                      ].map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Investigation Priority */}
            <Card padding="md">
              <CardHeader
                title="Priority Distribution"
                description="Investigations by priority level"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={[
                      { priority: 'Critical', count: 8 },
                      { priority: 'High', count: 24 },
                      { priority: 'Medium', count: 45 },
                      { priority: 'Low', count: 32 },
                    ]}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                    <XAxis
                      dataKey="priority"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <YAxis
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                    />
                    <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Evidence by Type */}
            <Card padding="md" className="lg:col-span-2">
              <CardHeader
                title="Evidence Collection"
                description="Evidence items by type"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={evidenceData?.data || []}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                    <XAxis
                      dataKey="type"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <YAxis
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                    />
                    <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} name="Items" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="targets">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Target Risk Distribution */}
            <Card padding="md">
              <CardHeader
                title="Risk Level Distribution"
                description="Targets categorized by risk level"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={riskDistribution?.data || []}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="count"
                      label={({ level, count }) => `${level}: ${count}`}
                    >
                      {(riskDistribution?.data || []).map((entry: any, index: number) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Target Status */}
            <Card padding="md">
              <CardHeader
                title="Target Status"
                description="Current status of all targets"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={[
                      { status: 'Active', count: 45 },
                      { status: 'Monitoring', count: 32 },
                      { status: 'Apprehended', count: 18 },
                      { status: 'Cleared', count: 12 },
                    ]}
                    layout="vertical"
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                    <XAxis
                      type="number"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <YAxis
                      dataKey="status"
                      type="category"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                      width={100}
                    />
                    <Tooltip />
                    <Bar dataKey="count" fill="#22c55e" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="operations">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Operations by Type */}
            <Card padding="md">
              <CardHeader
                title="Operations by Type"
                description="Distribution of operation types"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Surveillance', value: 35, color: '#6366f1' },
                        { name: 'Digital Forensics', value: 28, color: '#22c55e' },
                        { name: 'Interview', value: 22, color: '#f59e0b' },
                        { name: 'Asset Seizure', value: 15, color: '#ef4444' },
                        { name: 'Raid', value: 12, color: '#8b5cf6' },
                        { name: 'Undercover', value: 8, color: '#06b6d4' },
                      ]}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {[
                        '#6366f1', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'
                      ].map((color, index) => (
                        <Cell key={`cell-${index}`} fill={color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </Card>

            {/* Operations Status */}
            <Card padding="md">
              <CardHeader
                title="Operations Status"
                description="Current status of all operations"
              />
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={[
                      { status: 'In Progress', count: 28 },
                      { status: 'Planning', count: 18 },
                      { status: 'Approved', count: 12 },
                      { status: 'Completed', count: 45 },
                      { status: 'Cancelled', count: 5 },
                    ]}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                    <XAxis
                      dataKey="status"
                      tick={{ fill: '#9ca3af', fontSize: 11 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <YAxis
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                      axisLine={{ stroke: '#374151' }}
                    />
                    <Tooltip />
                    <Bar dataKey="count" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AnalyticsPage;
