import React from 'react';
import { cn } from '@utils/cn';
import { FiInbox, FiSearch, FiAlertCircle, FiFolder } from 'react-icons/fi';

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  variant?: 'default' | 'search' | 'error' | 'empty';
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  variant = 'default',
  className,
}) => {
  const defaultIcons = {
    default: <FiInbox className="h-12 w-12" />,
    search: <FiSearch className="h-12 w-12" />,
    error: <FiAlertCircle className="h-12 w-12" />,
    empty: <FiFolder className="h-12 w-12" />,
  };

  const displayIcon = icon || defaultIcons[variant];

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center py-12 px-4 text-center',
        className
      )}
    >
      <div className="text-gray-400 dark:text-gray-500 mb-4">{displayIcon}</div>
      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
        {title}
      </h3>
      {description && (
        <p className="text-sm text-gray-500 dark:text-gray-400 max-w-md mb-4">
          {description}
        </p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
};

export default EmptyState;
