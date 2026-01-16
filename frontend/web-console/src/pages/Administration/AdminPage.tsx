import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import toast from 'react-hot-toast';
import {
  FiUsers,
  FiSettings,
  FiKey,
  FiFileText,
  FiPlus,
  FiEdit2,
  FiTrash2,
  FiSearch,
  FiRefreshCw,
  FiCopy,
  FiEye,
  FiEyeOff,
  FiShield,
  FiActivity,
  FiDownload,
  FiFilter,
} from 'react-icons/fi';
import { Card, CardHeader, Button, Badge, Modal, Table, type Column } from '@components/common/UI';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@components/common/UI/Tabs';
import { Input, Select, Checkbox } from '@components/common/Forms';
import { PageLoader, Spinner } from '@components/common/Loading';
import { EmptyState } from '@components/common/UI/EmptyState';
import { adminService } from '@services/api';
import { User, UserRole, AuditLog } from '@types/index';
import { formatRelativeTime } from '@utils/formatters';

// Extend admin service with more methods for this page
const extendedAdminService = {
  ...adminService,
  async getRoles() {
    await new Promise(resolve => setTimeout(resolve, 200));
    return {
      data: [
        { id: 'admin', name: 'Administrator', description: 'Full system access', userCount: 3 },
        { id: 'investigator', name: 'Investigator', description: 'Manage investigations and targets', userCount: 12 },
        { id: 'analyst', name: 'Analyst', description: 'View and analyze data', userCount: 8 },
        { id: 'field_agent', name: 'Field Agent', description: 'Field operations access', userCount: 15 },
        { id: 'viewer', name: 'Viewer', description: 'Read-only access', userCount: 5 },
      ]
    };
  },
};

const AdminPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('users');
  const [searchQuery, setSearchQuery] = useState('');
  const [showUserModal, setShowUserModal] = useState(false);
  const [showApiKeyModal, setShowApiKeyModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);

  // Queries
  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => adminService.getUsers({ page: 1, pageSize: 50 }),
  });

  const { data: rolesData } = useQuery({
    queryKey: ['admin-roles'],
    queryFn: () => extendedAdminService.getRoles(),
  });

  const { data: apiKeysData, isLoading: apiKeysLoading } = useQuery({
    queryKey: ['admin-api-keys'],
    queryFn: () => adminService.getApiKeys(),
  });

  const { data: auditLogsData, isLoading: auditLogsLoading } = useQuery({
    queryKey: ['admin-audit-logs'],
    queryFn: () => adminService.getAuditLogs({}, { page: 1, pageSize: 100 }),
  });

  const { data: systemHealth } = useQuery({
    queryKey: ['admin-health'],
    queryFn: () => adminService.getSystemHealth(),
    refetchInterval: 30000,
  });

  // Mutations
  const createUserMutation = useMutation({
    mutationFn: adminService.createUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      setShowUserModal(false);
      toast.success('User created successfully');
    },
    onError: () => {
      toast.error('Failed to create user');
    },
  });

  const updateUserMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => adminService.updateUser(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      setShowUserModal(false);
      setSelectedUser(null);
      toast.success('User updated successfully');
    },
    onError: () => {
      toast.error('Failed to update user');
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: adminService.deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      toast.success('User deleted successfully');
    },
    onError: () => {
      toast.error('Failed to delete user');
    },
  });

  const createApiKeyMutation = useMutation({
    mutationFn: ({ name, permissions }: { name: string; permissions: string[] }) =>
      adminService.createApiKey(name, permissions),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['admin-api-keys'] });
      setNewApiKey(response.data?.key || null);
      toast.success('API key created successfully');
    },
    onError: () => {
      toast.error('Failed to create API key');
    },
  });

  const revokeApiKeyMutation = useMutation({
    mutationFn: adminService.revokeApiKey,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-api-keys'] });
      toast.success('API key revoked successfully');
    },
    onError: () => {
      toast.error('Failed to revoke API key');
    },
  });

  // User form
  const userForm = useFormik({
    initialValues: {
      username: selectedUser?.username || '',
      email: selectedUser?.email || '',
      firstName: selectedUser?.firstName || '',
      lastName: selectedUser?.lastName || '',
      role: selectedUser?.role || UserRole.VIEWER,
      department: selectedUser?.department || '',
      badgeNumber: selectedUser?.badgeNumber || '',
      password: '',
    },
    enableReinitialize: true,
    validationSchema: Yup.object({
      username: Yup.string().required('Username is required'),
      email: Yup.string().email('Invalid email').required('Email is required'),
      firstName: Yup.string().required('First name is required'),
      lastName: Yup.string().required('Last name is required'),
      role: Yup.string().required('Role is required'),
      password: selectedUser
        ? Yup.string().min(8, 'Password must be at least 8 characters')
        : Yup.string().min(8, 'Password must be at least 8 characters').required('Password is required'),
    }),
    onSubmit: (values) => {
      if (selectedUser) {
        const { password, ...data } = values;
        updateUserMutation.mutate({
          id: selectedUser.id,
          data: password ? values : data,
        });
      } else {
        createUserMutation.mutate(values);
      }
    },
  });

  // API Key form
  const apiKeyForm = useFormik({
    initialValues: {
      name: '',
      permissions: [] as string[],
    },
    validationSchema: Yup.object({
      name: Yup.string().required('Name is required'),
      permissions: Yup.array().min(1, 'Select at least one permission'),
    }),
    onSubmit: (values) => {
      createApiKeyMutation.mutate(values);
    },
  });

  const handleEditUser = (user: User) => {
    setSelectedUser(user);
    setShowUserModal(true);
  };

  const handleDeleteUser = (userId: string) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      deleteUserMutation.mutate(userId);
    }
  };

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    toast.success('API key copied to clipboard');
  };

  const handleRevokeKey = (keyId: string) => {
    if (window.confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) {
      revokeApiKeyMutation.mutate(keyId);
    }
  };

  // Filter users by search query
  const filteredUsers = (usersData?.data || []).filter(
    (user: User) =>
      user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.firstName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.lastName.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const userColumns: Column<User>[] = [
    {
      key: 'user',
      header: 'User',
      render: (user) => (
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-full bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center">
            <span className="text-sm font-medium text-primary-600 dark:text-primary-300">
              {user.firstName[0]}{user.lastName[0]}
            </span>
          </div>
          <div>
            <p className="font-medium text-gray-900 dark:text-white">
              {user.firstName} {user.lastName}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">@{user.username}</p>
          </div>
        </div>
      ),
    },
    {
      key: 'email',
      header: 'Email',
      render: (user) => (
        <span className="text-gray-600 dark:text-gray-300">{user.email}</span>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      render: (user) => (
        <Badge variant={user.role === UserRole.ADMIN ? 'danger' : 'primary'}>
          {user.role}
        </Badge>
      ),
    },
    {
      key: 'department',
      header: 'Department',
      render: (user) => (
        <span className="text-gray-600 dark:text-gray-300">
          {user.department || '-'}
        </span>
      ),
    },
    {
      key: 'mfa',
      header: 'MFA',
      render: (user) => (
        <Badge variant={user.mfaEnabled ? 'success' : 'warning'} dot>
          {user.mfaEnabled ? 'Enabled' : 'Disabled'}
        </Badge>
      ),
    },
    {
      key: 'lastLogin',
      header: 'Last Login',
      render: (user) => (
        <span className="text-gray-500 dark:text-gray-400">
          {user.lastLogin ? formatRelativeTime(user.lastLogin) : 'Never'}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      align: 'right',
      render: (user) => (
        <div className="flex items-center gap-2 justify-end">
          <button
            onClick={(e) => { e.stopPropagation(); handleEditUser(user); }}
            className="p-1 text-gray-400 hover:text-primary-600 transition-colors"
            title="Edit user"
          >
            <FiEdit2 className="h-4 w-4" />
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); handleDeleteUser(user.id); }}
            className="p-1 text-gray-400 hover:text-danger-600 transition-colors"
            title="Delete user"
          >
            <FiTrash2 className="h-4 w-4" />
          </button>
        </div>
      ),
    },
  ];

  const auditLogColumns: Column<AuditLog>[] = [
    {
      key: 'timestamp',
      header: 'Time',
      render: (log) => (
        <span className="text-gray-500 dark:text-gray-400">
          {formatRelativeTime(log.timestamp)}
        </span>
      ),
    },
    {
      key: 'userName',
      header: 'User',
      render: (log) => (
        <span className="font-medium text-gray-900 dark:text-white">{log.userName}</span>
      ),
    },
    {
      key: 'action',
      header: 'Action',
      render: (log) => (
        <Badge
          variant={
            log.action.includes('delete') ? 'danger' :
            log.action.includes('create') ? 'success' :
            log.action.includes('update') ? 'warning' : 'default'
          }
        >
          {log.action}
        </Badge>
      ),
    },
    {
      key: 'entityType',
      header: 'Entity',
      render: (log) => (
        <span className="text-gray-600 dark:text-gray-300">
          {log.entityType} ({log.entityId.substring(0, 8)}...)
        </span>
      ),
    },
    {
      key: 'ipAddress',
      header: 'IP Address',
      render: (log) => (
        <code className="text-sm text-gray-500 dark:text-gray-400">{log.ipAddress}</code>
      ),
    },
  ];

  const permissionOptions = [
    { value: 'read:investigations', label: 'Read Investigations' },
    { value: 'write:investigations', label: 'Write Investigations' },
    { value: 'read:targets', label: 'Read Targets' },
    { value: 'write:targets', label: 'Write Targets' },
    { value: 'read:evidence', label: 'Read Evidence' },
    { value: 'write:evidence', label: 'Write Evidence' },
    { value: 'read:operations', label: 'Read Operations' },
    { value: 'write:operations', label: 'Write Operations' },
    { value: 'read:intelligence', label: 'Read Intelligence' },
    { value: 'write:intelligence', label: 'Write Intelligence' },
  ];

  if (usersLoading) {
    return <PageLoader message="Loading administration..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Administration</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Manage users, roles, API keys, and system settings
          </p>
        </div>
      </div>

      {/* System Health Overview */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card padding="sm">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-success-100 p-2 dark:bg-success-900/30">
              <FiActivity className="h-5 w-5 text-success-600 dark:text-success-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">System Status</p>
              <p className="font-semibold text-success-600 dark:text-success-400">Operational</p>
            </div>
          </div>
        </Card>
        <Card padding="sm">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-primary-100 p-2 dark:bg-primary-900/30">
              <FiUsers className="h-5 w-5 text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Users</p>
              <p className="font-semibold text-gray-900 dark:text-white">
                {usersData?.data?.length || 0}
              </p>
            </div>
          </div>
        </Card>
        <Card padding="sm">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-warning-100 p-2 dark:bg-warning-900/30">
              <FiKey className="h-5 w-5 text-warning-600 dark:text-warning-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Active API Keys</p>
              <p className="font-semibold text-gray-900 dark:text-white">
                {apiKeysData?.data?.length || 0}
              </p>
            </div>
          </div>
        </Card>
        <Card padding="sm">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-purple-100 p-2 dark:bg-purple-900/30">
              <FiShield className="h-5 w-5 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Security Score</p>
              <p className="font-semibold text-gray-900 dark:text-white">98/100</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} defaultValue="users">
        <TabsList>
          <TabsTrigger value="users">
            <span className="flex items-center gap-2">
              <FiUsers className="h-4 w-4" />
              Users
            </span>
          </TabsTrigger>
          <TabsTrigger value="roles">
            <span className="flex items-center gap-2">
              <FiShield className="h-4 w-4" />
              Roles
            </span>
          </TabsTrigger>
          <TabsTrigger value="api-keys">
            <span className="flex items-center gap-2">
              <FiKey className="h-4 w-4" />
              API Keys
            </span>
          </TabsTrigger>
          <TabsTrigger value="audit-logs">
            <span className="flex items-center gap-2">
              <FiFileText className="h-4 w-4" />
              Audit Logs
            </span>
          </TabsTrigger>
          <TabsTrigger value="settings">
            <span className="flex items-center gap-2">
              <FiSettings className="h-4 w-4" />
              Settings
            </span>
          </TabsTrigger>
        </TabsList>

        {/* Users Tab */}
        <TabsContent value="users">
          <Card>
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
              <div className="relative flex-1 max-w-md">
                <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search users..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
              <Button
                onClick={() => { setSelectedUser(null); userForm.resetForm(); setShowUserModal(true); }}
                leftIcon={<FiPlus className="h-4 w-4" />}
              >
                Add User
              </Button>
            </div>
            <Table
              columns={userColumns}
              data={filteredUsers}
              keyExtractor={(user) => user.id}
              emptyMessage="No users found"
            />
          </Card>
        </TabsContent>

        {/* Roles Tab */}
        <TabsContent value="roles">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {(rolesData?.data || []).map((role: any) => (
              <Card key={role.id} padding="md" variant="bordered">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="rounded-full bg-primary-100 p-2 dark:bg-primary-900/30">
                      <FiShield className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 dark:text-white">{role.name}</h3>
                      <p className="text-sm text-gray-500 dark:text-gray-400">{role.description}</p>
                    </div>
                  </div>
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {role.userCount} users
                  </span>
                  <Button variant="ghost" size="sm">
                    Edit Permissions
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* API Keys Tab */}
        <TabsContent value="api-keys">
          <Card>
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">API Keys</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Manage API keys for external integrations
                </p>
              </div>
              <Button
                onClick={() => { apiKeyForm.resetForm(); setNewApiKey(null); setShowApiKeyModal(true); }}
                leftIcon={<FiPlus className="h-4 w-4" />}
              >
                Create API Key
              </Button>
            </div>
            {apiKeysLoading ? (
              <div className="flex justify-center py-8">
                <Spinner size="lg" />
              </div>
            ) : (apiKeysData?.data || []).length === 0 ? (
              <EmptyState
                title="No API Keys"
                description="Create your first API key to enable external integrations"
                action={
                  <Button
                    onClick={() => setShowApiKeyModal(true)}
                    leftIcon={<FiPlus className="h-4 w-4" />}
                  >
                    Create API Key
                  </Button>
                }
              />
            ) : (
              <div className="space-y-4">
                {(apiKeysData?.data || []).map((key: any) => (
                  <div
                    key={key.id}
                    className="flex items-center justify-between p-4 border border-gray-200 dark:border-dark-700 rounded-lg"
                  >
                    <div className="flex items-center gap-4">
                      <div className="rounded-full bg-gray-100 p-2 dark:bg-dark-700">
                        <FiKey className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                      </div>
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">{key.name}</p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          Created: {formatRelativeTime(key.createdAt)}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <code className="px-3 py-1 bg-gray-100 dark:bg-dark-700 rounded text-sm">
                        {key.prefix}...
                      </code>
                      <Badge variant={key.active ? 'success' : 'danger'} dot>
                        {key.active ? 'Active' : 'Revoked'}
                      </Badge>
                      {key.active && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleRevokeKey(key.id)}
                          className="text-danger-600"
                        >
                          Revoke
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </TabsContent>

        {/* Audit Logs Tab */}
        <TabsContent value="audit-logs">
          <Card>
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">Audit Logs</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  System activity and security events
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" leftIcon={<FiFilter className="h-4 w-4" />}>
                  Filter
                </Button>
                <Button variant="outline" size="sm" leftIcon={<FiDownload className="h-4 w-4" />}>
                  Export
                </Button>
              </div>
            </div>
            {auditLogsLoading ? (
              <div className="flex justify-center py-8">
                <Spinner size="lg" />
              </div>
            ) : (
              <Table
                columns={auditLogColumns}
                data={auditLogsData?.data || []}
                keyExtractor={(log) => log.id}
                emptyMessage="No audit logs available"
              />
            )}
          </Card>
        </TabsContent>

        {/* Settings Tab */}
        <TabsContent value="settings">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card padding="md">
              <CardHeader
                title="Security Settings"
                description="Configure system security policies"
              />
              <div className="space-y-4">
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Enforce Two-Factor Authentication
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Require MFA for all user accounts
                    </p>
                  </div>
                  <input type="checkbox" className="toggle" defaultChecked />
                </div>
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Session Timeout
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Auto-logout after inactivity
                    </p>
                  </div>
                  <Select className="w-32">
                    <option value="15">15 minutes</option>
                    <option value="30">30 minutes</option>
                    <option value="60">1 hour</option>
                    <option value="120">2 hours</option>
                  </Select>
                </div>
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Password Complexity
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Minimum requirements for passwords
                    </p>
                  </div>
                  <Select className="w-32">
                    <option value="basic">Basic</option>
                    <option value="medium">Medium</option>
                    <option value="strong">Strong</option>
                  </Select>
                </div>
                <div className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      IP Whitelist
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Restrict access to specific IPs
                    </p>
                  </div>
                  <Button variant="outline" size="sm">Configure</Button>
                </div>
              </div>
            </Card>

            <Card padding="md">
              <CardHeader
                title="Data Retention"
                description="Configure data storage policies"
              />
              <div className="space-y-4">
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Audit Log Retention
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      How long to keep audit logs
                    </p>
                  </div>
                  <Select className="w-32">
                    <option value="90">90 days</option>
                    <option value="180">180 days</option>
                    <option value="365">1 year</option>
                    <option value="730">2 years</option>
                  </Select>
                </div>
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Backup Frequency
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Automatic database backups
                    </p>
                  </div>
                  <Select className="w-32">
                    <option value="hourly">Hourly</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </Select>
                </div>
                <div className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Evidence Storage
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Configure evidence file storage
                    </p>
                  </div>
                  <Button variant="outline" size="sm">Configure</Button>
                </div>
              </div>
            </Card>

            <Card padding="md">
              <CardHeader
                title="Notification Settings"
                description="Configure system notifications"
              />
              <div className="space-y-4">
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Email Notifications
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Send system alerts via email
                    </p>
                  </div>
                  <input type="checkbox" className="toggle" defaultChecked />
                </div>
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Slack Integration
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Send alerts to Slack channels
                    </p>
                  </div>
                  <Button variant="outline" size="sm">Connect</Button>
                </div>
                <div className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Webhook Notifications
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Send events to external services
                    </p>
                  </div>
                  <Button variant="outline" size="sm">Configure</Button>
                </div>
              </div>
            </Card>

            <Card padding="md">
              <CardHeader
                title="System Maintenance"
                description="Manage system maintenance tasks"
              />
              <div className="space-y-4">
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Clear Cache
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Clear system and application cache
                    </p>
                  </div>
                  <Button variant="outline" size="sm" leftIcon={<FiRefreshCw className="h-4 w-4" />}>
                    Clear
                  </Button>
                </div>
                <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Database Optimization
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Optimize database performance
                    </p>
                  </div>
                  <Button variant="outline" size="sm">Optimize</Button>
                </div>
                <div className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      Export System Data
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Export all system data for backup
                    </p>
                  </div>
                  <Button variant="outline" size="sm" leftIcon={<FiDownload className="h-4 w-4" />}>
                    Export
                  </Button>
                </div>
              </div>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* User Modal */}
      <Modal
        isOpen={showUserModal}
        onClose={() => { setShowUserModal(false); setSelectedUser(null); }}
        title={selectedUser ? 'Edit User' : 'Create User'}
        size="lg"
      >
        <form onSubmit={userForm.handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="First Name"
              {...userForm.getFieldProps('firstName')}
              error={userForm.touched.firstName && userForm.errors.firstName ? userForm.errors.firstName : undefined}
            />
            <Input
              label="Last Name"
              {...userForm.getFieldProps('lastName')}
              error={userForm.touched.lastName && userForm.errors.lastName ? userForm.errors.lastName : undefined}
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Username"
              {...userForm.getFieldProps('username')}
              error={userForm.touched.username && userForm.errors.username ? userForm.errors.username : undefined}
            />
            <Input
              label="Email"
              type="email"
              {...userForm.getFieldProps('email')}
              error={userForm.touched.email && userForm.errors.email ? userForm.errors.email : undefined}
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Select
              label="Role"
              {...userForm.getFieldProps('role')}
              error={userForm.touched.role && userForm.errors.role ? userForm.errors.role : undefined}
            >
              <option value={UserRole.ADMIN}>Administrator</option>
              <option value={UserRole.INVESTIGATOR}>Investigator</option>
              <option value={UserRole.ANALYST}>Analyst</option>
              <option value={UserRole.FIELD_AGENT}>Field Agent</option>
              <option value={UserRole.VIEWER}>Viewer</option>
            </Select>
            <Input
              label="Department"
              {...userForm.getFieldProps('department')}
              placeholder="e.g., Cyber Crimes Unit"
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Badge Number"
              {...userForm.getFieldProps('badgeNumber')}
              placeholder="e.g., A-12345"
            />
            <Input
              label={selectedUser ? 'New Password (optional)' : 'Password'}
              type="password"
              {...userForm.getFieldProps('password')}
              error={userForm.touched.password && userForm.errors.password ? userForm.errors.password : undefined}
              hint={selectedUser ? 'Leave blank to keep current password' : undefined}
            />
          </div>
          <div className="flex justify-end gap-3 pt-4">
            <Button variant="ghost" type="button" onClick={() => setShowUserModal(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              loading={createUserMutation.isPending || updateUserMutation.isPending}
            >
              {selectedUser ? 'Update User' : 'Create User'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* API Key Modal */}
      <Modal
        isOpen={showApiKeyModal}
        onClose={() => { setShowApiKeyModal(false); setNewApiKey(null); }}
        title="Create API Key"
        size="md"
      >
        {newApiKey ? (
          <div className="space-y-4">
            <div className="p-4 bg-success-50 dark:bg-success-900/20 border border-success-200 dark:border-success-800 rounded-lg">
              <p className="text-sm text-success-800 dark:text-success-200 mb-2">
                API key created successfully! Make sure to copy it now, you won't be able to see it again.
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 p-2 bg-white dark:bg-dark-800 border rounded text-sm font-mono overflow-x-auto">
                  {showKey ? newApiKey : '****************************************'}
                </code>
                <button
                  onClick={() => setShowKey(!showKey)}
                  className="p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
                >
                  {showKey ? <FiEyeOff className="h-5 w-5" /> : <FiEye className="h-5 w-5" />}
                </button>
                <button
                  onClick={() => handleCopyKey(newApiKey)}
                  className="p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
                >
                  <FiCopy className="h-5 w-5" />
                </button>
              </div>
            </div>
            <div className="flex justify-end">
              <Button onClick={() => { setShowApiKeyModal(false); setNewApiKey(null); }}>
                Done
              </Button>
            </div>
          </div>
        ) : (
          <form onSubmit={apiKeyForm.handleSubmit} className="space-y-4">
            <Input
              label="Key Name"
              placeholder="e.g., Integration API Key"
              {...apiKeyForm.getFieldProps('name')}
              error={apiKeyForm.touched.name && apiKeyForm.errors.name ? apiKeyForm.errors.name : undefined}
            />
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Permissions
              </label>
              <div className="space-y-2 max-h-60 overflow-y-auto border border-gray-200 dark:border-dark-700 rounded-lg p-3">
                {permissionOptions.map((perm) => (
                  <Checkbox
                    key={perm.value}
                    label={perm.label}
                    checked={apiKeyForm.values.permissions.includes(perm.value)}
                    onChange={(e) => {
                      const newPerms = e.target.checked
                        ? [...apiKeyForm.values.permissions, perm.value]
                        : apiKeyForm.values.permissions.filter((p) => p !== perm.value);
                      apiKeyForm.setFieldValue('permissions', newPerms);
                    }}
                  />
                ))}
              </div>
              {apiKeyForm.touched.permissions && apiKeyForm.errors.permissions && (
                <p className="mt-1 text-sm text-danger-600">{apiKeyForm.errors.permissions as string}</p>
              )}
            </div>
            <div className="flex justify-end gap-3 pt-4">
              <Button variant="ghost" type="button" onClick={() => setShowApiKeyModal(false)}>
                Cancel
              </Button>
              <Button type="submit" loading={createApiKeyMutation.isPending}>
                Create Key
              </Button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
};

export default AdminPage;
