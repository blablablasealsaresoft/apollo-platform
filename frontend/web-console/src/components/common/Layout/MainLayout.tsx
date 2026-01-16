import React, { useState, useEffect } from 'react';
import { Outlet, useNavigate, useLocation, Link } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { logout } from '@store/slices/authSlice';
import {
  FiHome,
  FiFolder,
  FiUsers,
  FiFileText,
  FiActivity,
  FiSettings,
  FiLogOut,
  FiMenu,
  FiBell,
  FiSearch,
  FiX,
  FiBarChart2,
  FiShield,
  FiMap,
  FiEye,
  FiGlobe,
  FiCpu,
} from 'react-icons/fi';
import { cn } from '@utils/cn';
import { ConnectionStatusDot, ConnectionStatusBanner } from '@components/common/UI/ConnectionStatusIndicator';
import { useWebSocketConnection, useAlerts, useNotifications } from '@hooks/useWebSocket';
import NotificationPanel from '@components/common/UI/NotificationPanel';

const MainLayout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notificationPanelOpen, setNotificationPanelOpen] = useState(false);
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const user = useAppSelector((state) => state.auth.user);
  const token = useAppSelector((state) => state.auth.token);
  const unreadAlerts = useAppSelector((state) => state.alerts.unreadCount);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  // Close mobile menu on resize to desktop
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 1024) {
        setMobileMenuOpen(false);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Initialize WebSocket connection
  const { connect, disconnect, isConnected } = useWebSocketConnection();

  // Real-time alerts and notifications via WebSocket
  const { criticalCount } = useAlerts();
  const { unreadCount: notificationCount } = useNotifications();

  // Connect WebSocket when component mounts with auth token
  useEffect(() => {
    if (token && !isConnected) {
      connect(token);
    }
    return () => {
      // Disconnect on unmount if needed
    };
  }, [token, isConnected, connect]);

  const handleLogout = () => {
    dispatch(logout());
    navigate('/login');
  };

  const mainNavigation = [
    { name: 'Dashboard', href: '/dashboard', icon: FiHome },
    { name: 'Investigations', href: '/investigations', icon: FiFolder },
    { name: 'Targets', href: '/targets', icon: FiUsers },
    { name: 'Evidence', href: '/evidence', icon: FiFileText },
    { name: 'Intelligence', href: '/intelligence', icon: FiCpu },
    { name: 'Operations', href: '/operations', icon: FiActivity },
    { name: 'Analytics', href: '/analytics', icon: FiBarChart2 },
  ];

  const toolsNavigation = [
    { name: 'Geolocation', href: '/geolocation', icon: FiMap },
    { name: 'Facial Recognition', href: '/facial-recognition', icon: FiEye },
    { name: 'Blockchain', href: '/blockchain', icon: FiGlobe },
  ];

  const settingsNavigation = [
    { name: 'Settings', href: '/settings', icon: FiSettings },
    { name: 'Administration', href: '/admin', icon: FiShield },
  ];

  const isActivePath = (href: string) => {
    if (href === '/dashboard') return location.pathname === '/dashboard' || location.pathname === '/';
    return location.pathname.startsWith(href);
  };

  const renderNavItem = (item: { name: string; href: string; icon: React.ComponentType<{ className?: string }> }, collapsed = false) => {
    const isActive = isActivePath(item.href);
    return (
      <Link
        key={item.name}
        to={item.href}
        className={cn(
          'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
          isActive
            ? 'bg-primary-50 text-primary-600 dark:bg-primary-900/20 dark:text-primary-400'
            : 'text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-700',
          collapsed && 'justify-center'
        )}
        title={collapsed ? item.name : undefined}
      >
        <item.icon className="h-5 w-5 flex-shrink-0" />
        {!collapsed && <span>{item.name}</span>}
      </Link>
    );
  };

  return (
    <div className="flex h-screen bg-gray-100 dark:bg-dark-900">
      {/* Mobile menu overlay */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Mobile sidebar */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-800 lg:hidden',
          'transform transition-transform duration-300 ease-in-out',
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <div className="flex h-16 items-center justify-between border-b border-gray-200 px-4 dark:border-dark-700">
          <h1 className="text-xl font-bold text-primary-600">Apollo</h1>
          <button
            onClick={() => setMobileMenuOpen(false)}
            className="rounded-md p-2 hover:bg-gray-100 dark:hover:bg-dark-700"
          >
            <FiX className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 space-y-6 overflow-y-auto p-4">
          {/* Main Navigation */}
          <div>
            <p className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
              Main
            </p>
            <div className="mt-2 space-y-1">
              {mainNavigation.map((item) => renderNavItem(item))}
            </div>
          </div>

          {/* Tools */}
          <div>
            <p className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
              Tools
            </p>
            <div className="mt-2 space-y-1">
              {toolsNavigation.map((item) => renderNavItem(item))}
            </div>
          </div>

          {/* Settings */}
          <div>
            <p className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
              Settings
            </p>
            <div className="mt-2 space-y-1">
              {settingsNavigation.map((item) => renderNavItem(item))}
            </div>
          </div>
        </nav>

        <div className="border-t border-gray-200 p-4 dark:border-dark-700">
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-900/20"
          >
            <FiLogOut className="h-5 w-5" />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      {/* Desktop sidebar */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-30 hidden flex-col border-r border-gray-200 bg-white transition-all duration-300 dark:border-dark-700 dark:bg-dark-800 lg:flex',
          sidebarOpen ? 'w-64' : 'w-20'
        )}
      >
        <div className="flex h-16 items-center justify-between border-b border-gray-200 px-4 dark:border-dark-700">
          {sidebarOpen && (
            <h1 className="text-xl font-bold text-primary-600">Apollo</h1>
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="rounded-md p-2 hover:bg-gray-100 dark:hover:bg-dark-700"
          >
            <FiMenu className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 space-y-6 overflow-y-auto p-4 scrollbar-thin">
          {/* Main Navigation */}
          <div>
            {sidebarOpen && (
              <p className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
                Main
              </p>
            )}
            <div className={cn('space-y-1', sidebarOpen && 'mt-2')}>
              {mainNavigation.map((item) => renderNavItem(item, !sidebarOpen))}
            </div>
          </div>

          {/* Tools */}
          <div>
            {sidebarOpen && (
              <p className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
                Tools
              </p>
            )}
            <div className={cn('space-y-1', sidebarOpen && 'mt-2')}>
              {toolsNavigation.map((item) => renderNavItem(item, !sidebarOpen))}
            </div>
          </div>

          {/* Settings */}
          <div>
            {sidebarOpen && (
              <p className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
                Settings
              </p>
            )}
            <div className={cn('space-y-1', sidebarOpen && 'mt-2')}>
              {settingsNavigation.map((item) => renderNavItem(item, !sidebarOpen))}
            </div>
          </div>
        </nav>

        <div className="border-t border-gray-200 p-4 dark:border-dark-700">
          <button
            onClick={handleLogout}
            className={cn(
              'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-900/20',
              !sidebarOpen && 'justify-center'
            )}
            title={!sidebarOpen ? 'Logout' : undefined}
          >
            <FiLogOut className="h-5 w-5" />
            {sidebarOpen && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div
        className={cn(
          'flex flex-1 flex-col transition-all duration-300',
          'lg:ml-20',
          sidebarOpen && 'lg:ml-64'
        )}
      >
        {/* Top Bar */}
        <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-gray-200 bg-white px-4 dark:border-dark-700 dark:bg-dark-800 sm:px-6">
          {/* Mobile menu button */}
          <button
            onClick={() => setMobileMenuOpen(true)}
            className="rounded-md p-2 hover:bg-gray-100 dark:hover:bg-dark-700 lg:hidden"
          >
            <FiMenu className="h-5 w-5" />
          </button>

          {/* Search - hidden on mobile, shown on sm+ */}
          <div className="hidden flex-1 items-center gap-4 sm:flex">
            <div className="relative w-full max-w-md">
              <FiSearch className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                placeholder="Search..."
                className="w-full rounded-md border border-gray-300 py-2 pl-10 pr-4 text-sm focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-dark-600 dark:bg-dark-700"
              />
            </div>
          </div>

          {/* Mobile search button */}
          <button className="rounded-md p-2 hover:bg-gray-100 dark:hover:bg-dark-700 sm:hidden">
            <FiSearch className="h-5 w-5" />
          </button>

          <div className="flex items-center gap-2 sm:gap-4">
            {/* Connection Status */}
            <ConnectionStatusDot className="hidden sm:block" />

            {/* Notifications Bell */}
            <button
              className="relative rounded-md p-2 hover:bg-gray-100 dark:hover:bg-dark-700"
              onClick={() => setNotificationPanelOpen(!notificationPanelOpen)}
            >
              <FiBell className="h-5 w-5" />
              {(unreadAlerts + notificationCount + criticalCount) > 0 && (
                <span className={cn(
                  "absolute right-1 top-1 flex h-4 w-4 items-center justify-center rounded-full text-xs text-white",
                  criticalCount > 0 ? "bg-danger-600 animate-pulse" : "bg-danger-600"
                )}>
                  {unreadAlerts + notificationCount}
                </span>
              )}
            </button>

            {/* User profile - simplified on mobile */}
            <div className="flex items-center gap-2 sm:gap-3">
              <div className="hidden text-right sm:block">
                <p className="text-sm font-medium">{user?.firstName} {user?.lastName}</p>
                <p className="text-xs text-gray-500">{user?.role}</p>
              </div>
              <div className="h-8 w-8 sm:h-10 sm:w-10 rounded-full bg-primary-600 flex items-center justify-center text-white font-semibold text-sm">
                {user?.firstName?.[0]}{user?.lastName?.[0]}
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 scrollbar-thin">
          <Outlet />
        </main>
      </div>

      {/* Notification Panel */}
      {notificationPanelOpen && (
        <NotificationPanel onClose={() => setNotificationPanelOpen(false)} />
      )}

      {/* Connection Status Banner (shows when reconnecting/failed) */}
      <ConnectionStatusBanner />
    </div>
  );
};

export default MainLayout;
