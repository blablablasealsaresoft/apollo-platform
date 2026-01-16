import React from 'react';
import { cn } from '@utils/cn';

export interface ProgressBarProps {
  value: number;
  max?: number;
  size?: 'xs' | 'sm' | 'md' | 'lg';
  variant?: 'primary' | 'success' | 'warning' | 'danger' | 'info';
  showLabel?: boolean;
  labelPosition?: 'top' | 'right' | 'inside';
  animated?: boolean;
  striped?: boolean;
  className?: string;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  max = 100,
  size = 'md',
  variant = 'primary',
  showLabel = false,
  labelPosition = 'right',
  animated = false,
  striped = false,
  className,
}) => {
  const percentage = Math.min(Math.max((value / max) * 100, 0), 100);

  const sizeStyles = {
    xs: 'h-1',
    sm: 'h-2',
    md: 'h-3',
    lg: 'h-4',
  };

  const variantStyles = {
    primary: 'bg-primary-500',
    success: 'bg-success-500',
    warning: 'bg-warning-500',
    danger: 'bg-danger-500',
    info: 'bg-blue-500',
  };

  const trackStyles = 'bg-gray-200 dark:bg-dark-700';

  const Label = () => (
    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
      {Math.round(percentage)}%
    </span>
  );

  return (
    <div className={cn('w-full', className)}>
      {showLabel && labelPosition === 'top' && (
        <div className="flex justify-between mb-1">
          <Label />
        </div>
      )}
      <div className="flex items-center gap-3">
        <div className={cn('flex-1 rounded-full overflow-hidden', trackStyles, sizeStyles[size])}>
          <div
            className={cn(
              'h-full rounded-full transition-all duration-300 ease-out',
              variantStyles[variant],
              striped && 'bg-stripes',
              animated && 'animate-progress'
            )}
            style={{ width: `${percentage}%` }}
            role="progressbar"
            aria-valuenow={value}
            aria-valuemin={0}
            aria-valuemax={max}
          >
            {showLabel && labelPosition === 'inside' && size === 'lg' && (
              <span className="px-2 text-xs font-medium text-white">
                {Math.round(percentage)}%
              </span>
            )}
          </div>
        </div>
        {showLabel && labelPosition === 'right' && <Label />}
      </div>
    </div>
  );
};

export default ProgressBar;
