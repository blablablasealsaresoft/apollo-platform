import React from 'react';
import { Spinner } from './Spinner';
import { cn } from '@utils/cn';

export interface LoadingOverlayProps {
  loading: boolean;
  message?: string;
  blur?: boolean;
  className?: string;
  children?: React.ReactNode;
}

export const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  loading,
  message,
  blur = true,
  className,
  children,
}) => {
  if (!loading) {
    return <>{children}</>;
  }

  return (
    <div className={cn('relative', className)}>
      {children}
      <div
        className={cn(
          'absolute inset-0 z-10 flex flex-col items-center justify-center',
          'bg-white/80 dark:bg-dark-900/80',
          blur && 'backdrop-blur-sm'
        )}
      >
        <Spinner size="lg" />
        {message && (
          <p className="mt-3 text-sm text-gray-600 dark:text-gray-400 animate-pulse">
            {message}
          </p>
        )}
      </div>
    </div>
  );
};

export default LoadingOverlay;
