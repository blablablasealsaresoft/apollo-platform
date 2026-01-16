import React from 'react';
import { cn } from '@utils/cn';
import { FiChevronLeft, FiChevronRight, FiChevronsLeft, FiChevronsRight } from 'react-icons/fi';

export interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  siblingCount?: number;
  showFirstLast?: boolean;
  showPageNumbers?: boolean;
  className?: string;
}

const range = (start: number, end: number): number[] => {
  const length = end - start + 1;
  return Array.from({ length }, (_, idx) => idx + start);
};

export const Pagination: React.FC<PaginationProps> = ({
  currentPage,
  totalPages,
  onPageChange,
  siblingCount = 1,
  showFirstLast = true,
  showPageNumbers = true,
  className,
}) => {
  const DOTS = '...';

  const paginationRange = React.useMemo(() => {
    const totalPageNumbers = siblingCount + 5;

    if (totalPageNumbers >= totalPages) {
      return range(1, totalPages);
    }

    const leftSiblingIndex = Math.max(currentPage - siblingCount, 1);
    const rightSiblingIndex = Math.min(currentPage + siblingCount, totalPages);

    const shouldShowLeftDots = leftSiblingIndex > 2;
    const shouldShowRightDots = rightSiblingIndex < totalPages - 2;

    const firstPageIndex = 1;
    const lastPageIndex = totalPages;

    if (!shouldShowLeftDots && shouldShowRightDots) {
      const leftItemCount = 3 + 2 * siblingCount;
      const leftRange = range(1, leftItemCount);
      return [...leftRange, DOTS, totalPages];
    }

    if (shouldShowLeftDots && !shouldShowRightDots) {
      const rightItemCount = 3 + 2 * siblingCount;
      const rightRange = range(totalPages - rightItemCount + 1, totalPages);
      return [firstPageIndex, DOTS, ...rightRange];
    }

    if (shouldShowLeftDots && shouldShowRightDots) {
      const middleRange = range(leftSiblingIndex, rightSiblingIndex);
      return [firstPageIndex, DOTS, ...middleRange, DOTS, lastPageIndex];
    }

    return range(1, totalPages);
  }, [totalPages, siblingCount, currentPage]);

  const buttonBaseStyles =
    'inline-flex items-center justify-center h-9 w-9 rounded-lg text-sm font-medium transition-colors';
  const buttonActiveStyles =
    'bg-primary-600 text-white';
  const buttonInactiveStyles =
    'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-dark-700';
  const buttonDisabledStyles =
    'opacity-50 cursor-not-allowed';

  if (totalPages <= 1) {
    return null;
  }

  return (
    <nav
      className={cn('flex items-center gap-1', className)}
      aria-label="Pagination"
    >
      {showFirstLast && (
        <button
          onClick={() => onPageChange(1)}
          disabled={currentPage === 1}
          className={cn(
            buttonBaseStyles,
            buttonInactiveStyles,
            currentPage === 1 && buttonDisabledStyles
          )}
          aria-label="First page"
        >
          <FiChevronsLeft className="h-4 w-4" />
        </button>
      )}

      <button
        onClick={() => onPageChange(currentPage - 1)}
        disabled={currentPage === 1}
        className={cn(
          buttonBaseStyles,
          buttonInactiveStyles,
          currentPage === 1 && buttonDisabledStyles
        )}
        aria-label="Previous page"
      >
        <FiChevronLeft className="h-4 w-4" />
      </button>

      {showPageNumbers &&
        paginationRange.map((page, index) =>
          page === DOTS ? (
            <span
              key={`dots-${index}`}
              className="h-9 w-9 flex items-center justify-center text-gray-400"
            >
              {DOTS}
            </span>
          ) : (
            <button
              key={page}
              onClick={() => onPageChange(page as number)}
              className={cn(
                buttonBaseStyles,
                currentPage === page ? buttonActiveStyles : buttonInactiveStyles
              )}
              aria-label={`Page ${page}`}
              aria-current={currentPage === page ? 'page' : undefined}
            >
              {page}
            </button>
          )
        )}

      <button
        onClick={() => onPageChange(currentPage + 1)}
        disabled={currentPage === totalPages}
        className={cn(
          buttonBaseStyles,
          buttonInactiveStyles,
          currentPage === totalPages && buttonDisabledStyles
        )}
        aria-label="Next page"
      >
        <FiChevronRight className="h-4 w-4" />
      </button>

      {showFirstLast && (
        <button
          onClick={() => onPageChange(totalPages)}
          disabled={currentPage === totalPages}
          className={cn(
            buttonBaseStyles,
            buttonInactiveStyles,
            currentPage === totalPages && buttonDisabledStyles
          )}
          aria-label="Last page"
        >
          <FiChevronsRight className="h-4 w-4" />
        </button>
      )}
    </nav>
  );
};

// Page size selector
export interface PageSizeSelectorProps {
  pageSize: number;
  onPageSizeChange: (size: number) => void;
  options?: number[];
  className?: string;
}

export const PageSizeSelector: React.FC<PageSizeSelectorProps> = ({
  pageSize,
  onPageSizeChange,
  options = [10, 25, 50, 100],
  className,
}) => {
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <label className="text-sm text-gray-600 dark:text-gray-400">Show</label>
      <select
        value={pageSize}
        onChange={(e) => onPageSizeChange(Number(e.target.value))}
        className="h-9 px-2 rounded-lg border border-gray-300 dark:border-dark-600 bg-white dark:bg-dark-800 text-sm text-gray-700 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-primary-500"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
      <span className="text-sm text-gray-600 dark:text-gray-400">per page</span>
    </div>
  );
};

export default Pagination;
