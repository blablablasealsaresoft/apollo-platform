import React from 'react';
import { cn } from '@utils/cn';

export interface ContentLoaderProps {
  type?: 'card' | 'list' | 'table' | 'profile' | 'article';
  count?: number;
  className?: string;
}

const Pulse: React.FC<{ className?: string }> = ({ className }) => (
  <div className={cn('animate-pulse bg-gray-200 dark:bg-dark-700 rounded', className)} />
);

const CardLoader: React.FC = () => (
  <div className="p-6 bg-white dark:bg-dark-800 rounded-lg shadow-sm space-y-4">
    <div className="flex items-center gap-4">
      <Pulse className="w-12 h-12 rounded-full" />
      <div className="flex-1 space-y-2">
        <Pulse className="h-4 w-3/4" />
        <Pulse className="h-3 w-1/2" />
      </div>
    </div>
    <Pulse className="h-4 w-full" />
    <Pulse className="h-4 w-5/6" />
    <Pulse className="h-4 w-4/6" />
    <div className="flex gap-2 pt-2">
      <Pulse className="h-8 w-20 rounded-md" />
      <Pulse className="h-8 w-20 rounded-md" />
    </div>
  </div>
);

const ListLoader: React.FC = () => (
  <div className="p-4 bg-white dark:bg-dark-800 rounded-lg shadow-sm">
    <div className="flex items-center gap-4">
      <Pulse className="w-10 h-10 rounded-full" />
      <div className="flex-1 space-y-2">
        <Pulse className="h-4 w-1/3" />
        <Pulse className="h-3 w-1/2" />
      </div>
      <Pulse className="h-6 w-16 rounded-md" />
    </div>
  </div>
);

const TableLoader: React.FC = () => (
  <div className="bg-white dark:bg-dark-800 rounded-lg shadow-sm overflow-hidden">
    {/* Header */}
    <div className="flex gap-4 p-4 border-b border-gray-200 dark:border-dark-700">
      {[1, 2, 3, 4].map((i) => (
        <Pulse key={i} className="h-4 flex-1" />
      ))}
    </div>
    {/* Rows */}
    {[1, 2, 3, 4, 5].map((row) => (
      <div key={row} className="flex gap-4 p-4 border-b border-gray-200 dark:border-dark-700 last:border-b-0">
        {[1, 2, 3, 4].map((col) => (
          <Pulse key={col} className="h-4 flex-1" />
        ))}
      </div>
    ))}
  </div>
);

const ProfileLoader: React.FC = () => (
  <div className="p-6 bg-white dark:bg-dark-800 rounded-lg shadow-sm space-y-6">
    <div className="flex flex-col items-center text-center">
      <Pulse className="w-24 h-24 rounded-full mb-4" />
      <Pulse className="h-6 w-40 mb-2" />
      <Pulse className="h-4 w-24" />
    </div>
    <div className="grid grid-cols-3 gap-4 pt-4 border-t border-gray-200 dark:border-dark-700">
      {[1, 2, 3].map((i) => (
        <div key={i} className="text-center">
          <Pulse className="h-8 w-16 mx-auto mb-2" />
          <Pulse className="h-4 w-20 mx-auto" />
        </div>
      ))}
    </div>
    <div className="space-y-3 pt-4">
      <Pulse className="h-4 w-full" />
      <Pulse className="h-4 w-5/6" />
      <Pulse className="h-4 w-4/5" />
    </div>
  </div>
);

const ArticleLoader: React.FC = () => (
  <div className="space-y-6">
    <Pulse className="h-48 w-full rounded-lg" />
    <div className="space-y-4">
      <Pulse className="h-8 w-3/4" />
      <div className="flex items-center gap-4">
        <Pulse className="w-10 h-10 rounded-full" />
        <div className="flex-1 space-y-2">
          <Pulse className="h-4 w-24" />
          <Pulse className="h-3 w-32" />
        </div>
      </div>
    </div>
    <div className="space-y-3">
      <Pulse className="h-4 w-full" />
      <Pulse className="h-4 w-full" />
      <Pulse className="h-4 w-5/6" />
      <Pulse className="h-4 w-full" />
      <Pulse className="h-4 w-4/5" />
    </div>
  </div>
);

export const ContentLoader: React.FC<ContentLoaderProps> = ({
  type = 'card',
  count = 1,
  className,
}) => {
  const loaders = {
    card: CardLoader,
    list: ListLoader,
    table: TableLoader,
    profile: ProfileLoader,
    article: ArticleLoader,
  };

  const LoaderComponent = loaders[type];

  return (
    <div className={cn('space-y-4', className)}>
      {Array.from({ length: count }).map((_, index) => (
        <LoaderComponent key={index} />
      ))}
    </div>
  );
};

export default ContentLoader;
