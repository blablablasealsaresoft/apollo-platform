import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAppSelector } from '@store/hooks';
import toast from 'react-hot-toast';
import {
  FiUser,
  FiBell,
  FiMonitor,
  FiShield,
  FiSave,
  FiKey,
  FiLock,
  FiGlobe,
  FiSmartphone,
  FiTrash2,
  FiDownload,
  FiLogOut,
  FiAlertTriangle,
  FiCheck,
  FiX,
} from 'react-icons/fi';
import { Card, CardHeader, Button, Badge, Modal } from '@components/common/UI';
import { Input, Select, Switch, Checkbox } from '@components/common/Forms';
import { Spinner } from '@components/common/Loading';
import { settingsService } from '@services/api';
import { formatRelativeTime } from '@utils/formatters';

type SettingsTab = 'profile' | 'notifications' | 'display' | 'security' | 'sessions' | 'danger';

const SettingsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<SettingsTab>('profile');
  const [showMfaModal, setShowMfaModal] = useState(false);
  const [showDeleteAccountModal, setShowDeleteAccountModal] = useState(false);
  const user = useAppSelector((state) => state.auth.user);

  const tabs = [
    { id: 'profile' as const, label: 'Profile', icon: FiUser },
    { id: 'notifications' as const, label: 'Notifications', icon: FiBell },
    { id: 'display' as const, label: 'Display', icon: FiMonitor },
    { id: 'security' as const, label: 'Security', icon: FiShield },
    { id: 'sessions' as const, label: 'Sessions', icon: FiSmartphone },
    { id: 'danger' as const, label: 'Danger Zone', icon: FiAlertTriangle },
  ];

  // Fetch settings
  const { data: settings, isLoading: settingsLoading } = useQuery({
    queryKey: ['user-settings'],
    queryFn: () => settingsService.getSettings(),
  });

  // Fetch sessions
  const { data: sessions, isLoading: sessionsLoading } = useQuery({
    queryKey: ['user-sessions'],
    queryFn: () => settingsService.getSessions(),
    enabled: activeTab === 'sessions',
  });

  // Profile form
  const profileForm = useFormik({
    initialValues: {
      firstName: user?.firstName || '',
      lastName: user?.lastName || '',
      email: user?.email || '',
      department: user?.department || '',
      badgeNumber: user?.badgeNumber || '',
    },
    enableReinitialize: true,
    validationSchema: Yup.object({
      firstName: Yup.string().required('First name is required'),
      lastName: Yup.string().required('Last name is required'),
      email: Yup.string().email('Invalid email').required('Email is required'),
    }),
    onSubmit: async (values) => {
      try {
        await settingsService.updateProfile(values);
        toast.success('Profile updated successfully');
      } catch {
        toast.error('Failed to update profile');
      }
    },
  });

  // Notification settings form
  const notificationForm = useFormik({
    initialValues: {
      emailEnabled: settings?.data?.notifications?.emailEnabled ?? true,
      pushEnabled: settings?.data?.notifications?.pushEnabled ?? true,
      digestFrequency: settings?.data?.notifications?.digestFrequency ?? 'realtime',
    },
    enableReinitialize: true,
    onSubmit: async (values) => {
      try {
        await settingsService.updateNotificationSettings({
          ...values,
          alertTypes: [],
        });
        toast.success('Notification settings saved');
      } catch {
        toast.error('Failed to save notification settings');
      }
    },
  });

  // Display settings form
  const displayForm = useFormik({
    initialValues: {
      theme: settings?.data?.display?.theme ?? 'auto',
      language: settings?.data?.display?.language ?? 'en',
      timezone: settings?.data?.display?.timezone ?? 'UTC',
      dateFormat: settings?.data?.display?.dateFormat ?? 'YYYY-MM-DD',
      timeFormat: settings?.data?.display?.timeFormat ?? '24h',
    },
    enableReinitialize: true,
    onSubmit: async (values) => {
      try {
        await settingsService.updateDisplaySettings(values);
        toast.success('Display settings saved');
        // Apply theme change
        if (values.theme === 'dark') {
          document.documentElement.classList.add('dark');
        } else if (values.theme === 'light') {
          document.documentElement.classList.remove('dark');
        }
      } catch {
        toast.error('Failed to save display settings');
      }
    },
  });

  // Password change form
  const securityForm = useFormik({
    initialValues: {
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    },
    validationSchema: Yup.object({
      currentPassword: Yup.string().required('Current password is required'),
      newPassword: Yup.string()
        .min(8, 'Password must be at least 8 characters')
        .matches(/[a-z]/, 'Password must contain a lowercase letter')
        .matches(/[A-Z]/, 'Password must contain an uppercase letter')
        .matches(/[0-9]/, 'Password must contain a number')
        .required('New password is required'),
      confirmPassword: Yup.string()
        .oneOf([Yup.ref('newPassword')], 'Passwords must match')
        .required('Please confirm your password'),
    }),
    onSubmit: async (values) => {
      try {
        await settingsService.changePassword(values.currentPassword, values.newPassword);
        toast.success('Password changed successfully');
        securityForm.resetForm();
      } catch {
        toast.error('Failed to change password');
      }
    },
  });

  // Revoke session mutation
  const revokeSessionMutation = useMutation({
    mutationFn: settingsService.revokeSession,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-sessions'] });
      toast.success('Session revoked');
    },
    onError: () => {
      toast.error('Failed to revoke session');
    },
  });

  // Revoke all sessions mutation
  const revokeAllSessionsMutation = useMutation({
    mutationFn: settingsService.revokeAllSessions,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-sessions'] });
      toast.success('All other sessions revoked');
    },
    onError: () => {
      toast.error('Failed to revoke sessions');
    },
  });

  const handleExportData = async () => {
    try {
      await settingsService.exportUserData();
      toast.success('Data exported successfully');
    } catch {
      toast.error('Failed to export data');
    }
  };

  const handleToggleMfa = async () => {
    if (user?.mfaEnabled) {
      // Disable MFA
      const password = prompt('Enter your password to disable 2FA:');
      if (password) {
        try {
          await settingsService.disableMfa(password);
          toast.success('Two-factor authentication disabled');
        } catch {
          toast.error('Failed to disable 2FA');
        }
      }
    } else {
      // Enable MFA
      setShowMfaModal(true);
    }
  };

  if (settingsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Spinner size="xl" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Manage your account settings and preferences
        </p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar Navigation */}
        <div className="lg:w-64 flex-shrink-0">
          <nav className="space-y-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 text-sm font-medium rounded-lg transition-colors ${
                  activeTab === tab.id
                    ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'
                    : tab.id === 'danger'
                    ? 'text-danger-600 hover:bg-danger-50 dark:text-danger-400 dark:hover:bg-danger-900/20'
                    : 'text-gray-600 hover:bg-gray-50 dark:text-gray-400 dark:hover:bg-dark-700'
                }`}
              >
                <tab.icon className="h-5 w-5" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Main Content */}
        <div className="flex-1">
          {/* Profile Tab */}
          {activeTab === 'profile' && (
            <Card padding="md">
              <CardHeader
                title="Profile Information"
                description="Update your personal information"
              />
              <form onSubmit={profileForm.handleSubmit} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Input
                    label="First Name"
                    {...profileForm.getFieldProps('firstName')}
                    error={profileForm.touched.firstName ? profileForm.errors.firstName : undefined}
                  />
                  <Input
                    label="Last Name"
                    {...profileForm.getFieldProps('lastName')}
                    error={profileForm.touched.lastName ? profileForm.errors.lastName : undefined}
                  />
                </div>
                <Input
                  label="Email Address"
                  type="email"
                  {...profileForm.getFieldProps('email')}
                  error={profileForm.touched.email ? profileForm.errors.email : undefined}
                />
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Input
                    label="Department"
                    {...profileForm.getFieldProps('department')}
                    placeholder="e.g., Cyber Crimes Unit"
                  />
                  <Input
                    label="Badge Number"
                    {...profileForm.getFieldProps('badgeNumber')}
                    placeholder="e.g., A-12345"
                  />
                </div>
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    loading={profileForm.isSubmitting}
                    leftIcon={<FiSave className="h-4 w-4" />}
                  >
                    Save Changes
                  </Button>
                </div>
              </form>
            </Card>
          )}

          {/* Notifications Tab */}
          {activeTab === 'notifications' && (
            <Card padding="md">
              <CardHeader
                title="Notification Preferences"
                description="Manage how you receive notifications"
              />
              <form onSubmit={notificationForm.handleSubmit} className="space-y-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">Email Notifications</p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        Receive notifications via email
                      </p>
                    </div>
                    <Switch
                      checked={notificationForm.values.emailEnabled}
                      onChange={(e) => notificationForm.setFieldValue('emailEnabled', e.target.checked)}
                    />
                  </div>
                  <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-dark-700">
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">Push Notifications</p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        Receive real-time push notifications
                      </p>
                    </div>
                    <Switch
                      checked={notificationForm.values.pushEnabled}
                      onChange={(e) => notificationForm.setFieldValue('pushEnabled', e.target.checked)}
                    />
                  </div>
                </div>
                <Select
                  label="Digest Frequency"
                  value={notificationForm.values.digestFrequency}
                  onChange={(e) => notificationForm.setFieldValue('digestFrequency', e.target.value)}
                >
                  <option value="realtime">Real-time</option>
                  <option value="hourly">Hourly</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                </Select>
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    loading={notificationForm.isSubmitting}
                    leftIcon={<FiSave className="h-4 w-4" />}
                  >
                    Save Changes
                  </Button>
                </div>
              </form>
            </Card>
          )}

          {/* Display Tab */}
          {activeTab === 'display' && (
            <Card padding="md">
              <CardHeader
                title="Display Settings"
                description="Customize your display preferences"
              />
              <form onSubmit={displayForm.handleSubmit} className="space-y-6">
                <Select
                  label="Theme"
                  value={displayForm.values.theme}
                  onChange={(e) => displayForm.setFieldValue('theme', e.target.value)}
                >
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                  <option value="auto">System Default</option>
                </Select>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Select
                    label="Language"
                    value={displayForm.values.language}
                    onChange={(e) => displayForm.setFieldValue('language', e.target.value)}
                  >
                    <option value="en">English</option>
                    <option value="es">Spanish</option>
                    <option value="de">German</option>
                    <option value="fr">French</option>
                    <option value="ru">Russian</option>
                    <option value="ar">Arabic</option>
                  </Select>
                  <Select
                    label="Timezone"
                    value={displayForm.values.timezone}
                    onChange={(e) => displayForm.setFieldValue('timezone', e.target.value)}
                  >
                    <option value="UTC">UTC</option>
                    <option value="America/New_York">Eastern Time</option>
                    <option value="America/Chicago">Central Time</option>
                    <option value="America/Los_Angeles">Pacific Time</option>
                    <option value="Europe/London">London</option>
                    <option value="Europe/Berlin">Berlin</option>
                    <option value="Europe/Sofia">Sofia (Bulgaria)</option>
                    <option value="Asia/Dubai">Dubai</option>
                  </Select>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Select
                    label="Date Format"
                    value={displayForm.values.dateFormat}
                    onChange={(e) => displayForm.setFieldValue('dateFormat', e.target.value)}
                  >
                    <option value="YYYY-MM-DD">YYYY-MM-DD</option>
                    <option value="MM/DD/YYYY">MM/DD/YYYY</option>
                    <option value="DD/MM/YYYY">DD/MM/YYYY</option>
                    <option value="DD.MM.YYYY">DD.MM.YYYY</option>
                  </Select>
                  <Select
                    label="Time Format"
                    value={displayForm.values.timeFormat}
                    onChange={(e) => displayForm.setFieldValue('timeFormat', e.target.value)}
                  >
                    <option value="12h">12-hour</option>
                    <option value="24h">24-hour</option>
                  </Select>
                </div>
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    loading={displayForm.isSubmitting}
                    leftIcon={<FiSave className="h-4 w-4" />}
                  >
                    Save Changes
                  </Button>
                </div>
              </form>
            </Card>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              <Card padding="md">
                <CardHeader
                  title="Change Password"
                  description="Update your password regularly for security"
                />
                <form onSubmit={securityForm.handleSubmit} className="space-y-4">
                  <Input
                    label="Current Password"
                    type="password"
                    {...securityForm.getFieldProps('currentPassword')}
                    error={securityForm.touched.currentPassword ? securityForm.errors.currentPassword : undefined}
                  />
                  <Input
                    label="New Password"
                    type="password"
                    {...securityForm.getFieldProps('newPassword')}
                    error={securityForm.touched.newPassword ? securityForm.errors.newPassword : undefined}
                    hint="Minimum 8 characters with uppercase, lowercase, and number"
                  />
                  <Input
                    label="Confirm New Password"
                    type="password"
                    {...securityForm.getFieldProps('confirmPassword')}
                    error={securityForm.touched.confirmPassword ? securityForm.errors.confirmPassword : undefined}
                  />
                  <div className="flex justify-end">
                    <Button
                      type="submit"
                      loading={securityForm.isSubmitting}
                      leftIcon={<FiKey className="h-4 w-4" />}
                    >
                      Update Password
                    </Button>
                  </div>
                </form>
              </Card>

              <Card padding="md">
                <CardHeader
                  title="Two-Factor Authentication"
                  description="Add an extra layer of security to your account"
                />
                <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-dark-700 rounded-lg">
                  <div className="flex items-center gap-3">
                    <FiShield className="h-8 w-8 text-primary-600 dark:text-primary-400" />
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">
                        {user?.mfaEnabled ? '2FA is enabled' : '2FA is not enabled'}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {user?.mfaEnabled
                          ? 'Your account is protected with two-factor authentication'
                          : 'Enable 2FA for enhanced security'}
                      </p>
                    </div>
                  </div>
                  <Button
                    variant={user?.mfaEnabled ? 'outline' : 'primary'}
                    onClick={handleToggleMfa}
                  >
                    {user?.mfaEnabled ? 'Disable 2FA' : 'Enable 2FA'}
                  </Button>
                </div>
              </Card>
            </div>
          )}

          {/* Sessions Tab */}
          {activeTab === 'sessions' && (
            <Card padding="md">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Active Sessions</h2>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Manage your active login sessions
                  </p>
                </div>
                <Button
                  variant="outline"
                  onClick={() => revokeAllSessionsMutation.mutate()}
                  loading={revokeAllSessionsMutation.isPending}
                  leftIcon={<FiLogOut className="h-4 w-4" />}
                >
                  Sign out all other sessions
                </Button>
              </div>
              {sessionsLoading ? (
                <div className="flex justify-center py-8">
                  <Spinner size="lg" />
                </div>
              ) : (
                <div className="space-y-4">
                  {sessions?.data?.map((session: any) => (
                    <div
                      key={session.id}
                      className="flex items-center justify-between p-4 border border-gray-200 dark:border-dark-700 rounded-lg"
                    >
                      <div className="flex items-center gap-4">
                        <div className="rounded-full bg-gray-100 dark:bg-dark-700 p-2">
                          <FiSmartphone className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                        </div>
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">
                            {session.device}
                            {session.current && (
                              <Badge variant="success" size="sm" className="ml-2">
                                Current
                              </Badge>
                            )}
                          </p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">
                            {session.location} - {session.ipAddress}
                          </p>
                          <p className="text-xs text-gray-400 dark:text-gray-500">
                            Last active: {formatRelativeTime(session.lastActive)}
                          </p>
                        </div>
                      </div>
                      {!session.current && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => revokeSessionMutation.mutate(session.id)}
                          loading={revokeSessionMutation.isPending}
                        >
                          Revoke
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}

          {/* Danger Zone Tab */}
          {activeTab === 'danger' && (
            <div className="space-y-6">
              <Card padding="md" className="border-warning-500 dark:border-warning-600">
                <CardHeader
                  title="Export Your Data"
                  description="Download a copy of all your data"
                />
                <div className="flex justify-end">
                  <Button
                    variant="outline"
                    onClick={handleExportData}
                    leftIcon={<FiDownload className="h-4 w-4" />}
                  >
                    Export Data
                  </Button>
                </div>
              </Card>

              <Card padding="md" className="border-danger-500 dark:border-danger-600">
                <CardHeader
                  title="Delete Account"
                  description="Permanently delete your account and all associated data. This action cannot be undone."
                />
                <div className="flex justify-end">
                  <Button
                    variant="danger"
                    onClick={() => setShowDeleteAccountModal(true)}
                    leftIcon={<FiTrash2 className="h-4 w-4" />}
                  >
                    Delete Account
                  </Button>
                </div>
              </Card>
            </div>
          )}
        </div>
      </div>

      {/* MFA Setup Modal */}
      <Modal
        isOpen={showMfaModal}
        onClose={() => setShowMfaModal(false)}
        title="Enable Two-Factor Authentication"
        size="md"
      >
        <div className="text-center">
          <p className="text-gray-500 dark:text-gray-400 mb-4">
            Scan the QR code with your authenticator app (e.g., Google Authenticator, Authy)
          </p>
          {/* QR Code would be displayed here */}
          <div className="w-48 h-48 mx-auto bg-gray-200 dark:bg-dark-700 rounded-lg flex items-center justify-center mb-4">
            <span className="text-gray-500">QR Code</span>
          </div>
          <Input
            label="Enter verification code"
            placeholder="000000"
            className="mb-4"
          />
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setShowMfaModal(false)}>
              Cancel
            </Button>
            <Button>Verify & Enable</Button>
          </div>
        </div>
      </Modal>

      {/* Delete Account Modal */}
      <Modal
        isOpen={showDeleteAccountModal}
        onClose={() => setShowDeleteAccountModal(false)}
        title="Delete Account"
        size="sm"
      >
        <div className="text-center">
          <FiAlertTriangle className="h-12 w-12 mx-auto text-danger-500 mb-4" />
          <p className="text-gray-500 dark:text-gray-400 mb-4">
            This action is permanent and cannot be undone. All your data will be deleted.
          </p>
          <Input
            label="Enter your password to confirm"
            type="password"
            className="mb-4"
          />
          <div className="flex justify-center gap-3">
            <Button variant="ghost" onClick={() => setShowDeleteAccountModal(false)}>
              Cancel
            </Button>
            <Button variant="danger">
              Delete My Account
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default SettingsPage;
