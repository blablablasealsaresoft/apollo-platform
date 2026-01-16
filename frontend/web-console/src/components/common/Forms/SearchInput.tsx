import React, { useState, useRef, useEffect } from 'react';
import { FiSearch, FiX, FiLoader } from 'react-icons/fi';
import { cn } from '@utils/cn';

export interface SearchInputProps {
  value?: string;
  onChange?: (value: string) => void;
  onSearch?: (value: string) => void;
  placeholder?: string;
  loading?: boolean;
  debounceMs?: number;
  autoFocus?: boolean;
  showClearButton?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const SearchInput: React.FC<SearchInputProps> = ({
  value: controlledValue,
  onChange,
  onSearch,
  placeholder = 'Search...',
  loading = false,
  debounceMs = 300,
  autoFocus = false,
  showClearButton = true,
  size = 'md',
  className,
}) => {
  const [internalValue, setInternalValue] = useState(controlledValue || '');
  const debounceRef = useRef<NodeJS.Timeout>();
  const inputRef = useRef<HTMLInputElement>(null);

  const value = controlledValue !== undefined ? controlledValue : internalValue;

  useEffect(() => {
    if (autoFocus && inputRef.current) {
      inputRef.current.focus();
    }
  }, [autoFocus]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;

    if (controlledValue === undefined) {
      setInternalValue(newValue);
    }

    onChange?.(newValue);

    // Debounce search
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    if (onSearch) {
      debounceRef.current = setTimeout(() => {
        onSearch(newValue);
      }, debounceMs);
    }
  };

  const handleClear = () => {
    if (controlledValue === undefined) {
      setInternalValue('');
    }
    onChange?.('');
    onSearch?.('');
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && onSearch) {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
      onSearch(value);
    }
    if (e.key === 'Escape') {
      handleClear();
    }
  };

  const sizeStyles = {
    sm: 'h-8 text-sm pl-8 pr-8',
    md: 'h-10 text-sm pl-10 pr-10',
    lg: 'h-12 text-base pl-12 pr-12',
  };

  const iconSizeStyles = {
    sm: 'h-4 w-4',
    md: 'h-5 w-5',
    lg: 'h-6 w-6',
  };

  const iconPositionStyles = {
    sm: 'left-2',
    md: 'left-3',
    lg: 'left-4',
  };

  return (
    <div className={cn('relative', className)}>
      <div className={cn('absolute top-1/2 -translate-y-1/2 text-gray-400', iconPositionStyles[size])}>
        {loading ? (
          <FiLoader className={cn('animate-spin', iconSizeStyles[size])} />
        ) : (
          <FiSearch className={iconSizeStyles[size]} />
        )}
      </div>
      <input
        ref={inputRef}
        type="text"
        value={value}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
        className={cn(
          'input w-full',
          sizeStyles[size]
        )}
      />
      {showClearButton && value && (
        <button
          type="button"
          onClick={handleClear}
          className={cn(
            'absolute top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors',
            size === 'sm' ? 'right-2' : size === 'md' ? 'right-3' : 'right-4'
          )}
        >
          <FiX className={iconSizeStyles[size]} />
        </button>
      )}
    </div>
  );
};

export default SearchInput;
