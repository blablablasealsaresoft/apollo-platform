import React, { useState } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
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
} from 'react-icons/fi';
import { cn } from '@utils/cn';

const MainLayout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const user = useAppSelector((state) => state.auth.user);
  const unreadAlerts = useAppSelector((state) => state.alerts.unreadCount);

  const handleLogout = () => {
    dispatch(logout());
    navigate('/login');
  };

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: FiHome },
    { name: 'Investigations', href: '/investigations', icon: FiFolder },
    { name: 'Targets', href: '/targets', icon: FiUsers },
    { name: 'Evidence', href: '/evidence', icon: FiFileText },
    { name: 'Intelligence', href: '/intelligence', icon: FiSearch },
    { name: 'Operations', href: '/operations', icon: FiActivity },
    { name: 'Settings', href: '/settings', icon: FiSettings },
  ];

  return (
    <div className="flex h-screen bg-gray-100 dark:bg-dark-900">
      {/* Sidebar */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 flex flex-col border-r border-gray-200 bg-white transition-all duration-300 dark:border-dark-700 dark:bg-dark-800',
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

        <nav className="flex-1 space-y-1 overflow-y-auto p-4">
          {navigation.map((item) => (
            <a
              key={item.name}
              href={item.href}
              className={cn(
                'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors hover:bg-gray-100 dark:hover:bg-dark-700',
                !sidebarOpen && 'justify-center'
              )}
            >
              <item.icon className="h-5 w-5" />
              {sidebarOpen && <span>{item.name}</span>}
            </a>
          ))}
        </nav>

        <div className="border-t border-gray-200 p-4 dark:border-dark-700">
          <button
            onClick={handleLogout}
            className={cn(
              'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-900/20',
              !sidebarOpen && 'justify-center'
            )}
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
          sidebarOpen ? 'ml-64' : 'ml-20'
        )}
      >
        {/* Top Bar */}
        <header className="flex h-16 items-center justify-between border-b border-gray-200 bg-white px-6 dark:border-dark-700 dark:bg-dark-800">
          <div className="flex flex-1 items-center gap-4">
            <div className="relative w-96">
              <FiSearch className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                placeholder="Search investigations, targets, evidence..."
                className="w-full rounded-md border border-gray-300 py-2 pl-10 pr-4 text-sm focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-dark-600 dark:bg-dark-700"
              />
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button className="relative rounded-md p-2 hover:bg-gray-100 dark:hover:bg-dark-700">
              <FiBell className="h-5 w-5" />
              {unreadAlerts > 0 && (
                <span className="absolute right-1 top-1 flex h-4 w-4 items-center justify-center rounded-full bg-danger-600 text-xs text-white">
                  {unreadAlerts}
                </span>
              )}
            </button>

            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-sm font-medium">{user?.firstName} {user?.lastName}</p>
                <p className="text-xs text-gray-500">{user?.role}</p>
              </div>
              <div className="h-10 w-10 rounded-full bg-primary-600 flex items-center justify-center text-white font-semibold">
                {user?.firstName?.[0]}{user?.lastName?.[0]}
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default MainLayout;
