import React from 'react';
import { cn } from '@utils/cn';

export interface TimelineItem {
  id: string;
  title: string;
  description?: string;
  timestamp: string;
  icon?: React.ReactNode;
  iconColor?: string;
  status?: 'completed' | 'current' | 'upcoming';
  content?: React.ReactNode;
}

export interface TimelineProps {
  items: TimelineItem[];
  className?: string;
  variant?: 'default' | 'compact' | 'alternating';
}

export const Timeline: React.FC<TimelineProps> = ({
  items,
  className,
  variant = 'default',
}) => {
  if (variant === 'alternating') {
    return (
      <div className={cn('relative', className)}>
        {/* Center line */}
        <div className="absolute left-1/2 top-0 bottom-0 w-0.5 bg-gray-200 dark:bg-dark-700 -translate-x-1/2" />

        {items.map((item, index) => (
          <div
            key={item.id}
            className={cn(
              'relative flex items-start gap-6 mb-8 last:mb-0',
              index % 2 === 0 ? 'flex-row' : 'flex-row-reverse'
            )}
          >
            {/* Content */}
            <div className={cn('flex-1', index % 2 === 0 ? 'text-right pr-8' : 'text-left pl-8')}>
              <div
                className={cn(
                  'inline-block p-4 rounded-lg bg-white dark:bg-dark-800 shadow-sm border border-gray-200 dark:border-dark-700',
                  index % 2 === 0 ? 'mr-4' : 'ml-4'
                )}
              >
                <p className="text-sm font-medium text-gray-900 dark:text-white">{item.title}</p>
                {item.description && (
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{item.description}</p>
                )}
                <p className="mt-2 text-xs text-gray-400 dark:text-gray-500">{item.timestamp}</p>
                {item.content}
              </div>
            </div>

            {/* Center dot */}
            <div className="absolute left-1/2 -translate-x-1/2 flex items-center justify-center">
              <div
                className={cn(
                  'w-4 h-4 rounded-full ring-4 ring-white dark:ring-dark-900',
                  item.iconColor || 'bg-primary-500'
                )}
              />
            </div>

            {/* Spacer */}
            <div className="flex-1" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className={cn('relative', className)}>
      {/* Line */}
      <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-gray-200 dark:bg-dark-700" />

      {items.map((item, index) => (
        <div key={item.id} className="relative flex items-start gap-4 pb-8 last:pb-0">
          {/* Dot/Icon */}
          <div className="relative z-10 flex items-center justify-center">
            {item.icon ? (
              <div
                className={cn(
                  'w-8 h-8 rounded-full flex items-center justify-center ring-4 ring-white dark:ring-dark-900',
                  item.iconColor || 'bg-primary-500 text-white'
                )}
              >
                {item.icon}
              </div>
            ) : (
              <div
                className={cn(
                  'w-3 h-3 rounded-full ring-4 ring-white dark:ring-dark-900',
                  item.status === 'completed'
                    ? 'bg-success-500'
                    : item.status === 'current'
                    ? 'bg-primary-500'
                    : 'bg-gray-300 dark:bg-dark-600',
                  item.iconColor
                )}
              />
            )}
          </div>

          {/* Content */}
          <div className={cn('flex-1 min-w-0', variant === 'compact' ? '-mt-1' : '')}>
            <div className="flex items-center gap-2">
              <p className="text-sm font-medium text-gray-900 dark:text-white">{item.title}</p>
              <span className="text-xs text-gray-400 dark:text-gray-500">{item.timestamp}</span>
            </div>
            {item.description && (
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{item.description}</p>
            )}
            {item.content}
          </div>
        </div>
      ))}
    </div>
  );
};

export default Timeline;
