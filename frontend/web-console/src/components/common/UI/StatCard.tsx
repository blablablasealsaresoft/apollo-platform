import React from 'react';
import { cn } from '@utils/cn';
import { FiArrowUp, FiArrowDown, FiMinus } from 'react-icons/fi';

export interface StatCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeLabel?: string;
  icon?: React.ReactNode;
  iconColor?: string;
  trend?: 'up' | 'down' | 'neutral';
  loading?: boolean;
  className?: string;
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  change,
  changeLabel,
  icon,
  iconColor = 'bg-primary-500',
  trend,
  loading = false,
  className,
  onClick,
}) => {
  const trendIcon = {
    up: <FiArrowUp className="h-4 w-4" />,
    down: <FiArrowDown className="h-4 w-4" />,
    neutral: <FiMinus className="h-4 w-4" />,
  };

  const trendColor = {
    up: 'text-success-600 dark:text-success-400',
    down: 'text-danger-600 dark:text-danger-400',
    neutral: 'text-gray-500 dark:text-gray-400',
  };

  if (loading) {
    return (
      <div className={cn('card animate-pulse', className)}>
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <div className="h-4 bg-gray-200 dark:bg-dark-700 rounded w-24 mb-3" />
            <div className="h-8 bg-gray-200 dark:bg-dark-700 rounded w-16" />
          </div>
          <div className="h-12 w-12 bg-gray-200 dark:bg-dark-700 rounded-full" />
        </div>
      </div>
    );
  }

  return (
    <div
      className={cn(
        'card transition-all',
        onClick && 'cursor-pointer hover:shadow-lg',
        className
      )}
      onClick={onClick}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
            {title}
          </p>
          <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
            {value}
          </p>
          {(change !== undefined || changeLabel) && (
            <div className="mt-2 flex items-center gap-1">
              {trend && (
                <span className={cn('flex items-center', trendColor[trend])}>
                  {trendIcon[trend]}
                </span>
              )}
              {change !== undefined && (
                <span
                  className={cn(
                    'text-sm font-medium',
                    trend ? trendColor[trend] : 'text-gray-500'
                  )}
                >
                  {change > 0 ? '+' : ''}
                  {change}%
                </span>
              )}
              {changeLabel && (
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {changeLabel}
                </span>
              )}
            </div>
          )}
        </div>
        {icon && (
          <div className={cn('rounded-full p-3', iconColor)}>
            <div className="h-6 w-6 text-white">{icon}</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default StatCard;
