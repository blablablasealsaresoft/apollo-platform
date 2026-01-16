import React, { useState, useRef, useEffect } from 'react';
import { cn } from '@utils/cn';
import { FiChevronDown } from 'react-icons/fi';

export interface DropdownItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
  disabled?: boolean;
  divider?: boolean;
  danger?: boolean;
  onClick?: () => void;
}

export interface DropdownProps {
  trigger: React.ReactNode;
  items: DropdownItem[];
  align?: 'left' | 'right';
  width?: 'auto' | 'trigger' | number;
  className?: string;
}

export const Dropdown: React.FC<DropdownProps> = ({
  trigger,
  items,
  align = 'left',
  width = 'auto',
  className,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, []);

  const handleItemClick = (item: DropdownItem) => {
    if (!item.disabled && !item.divider) {
      item.onClick?.();
      setIsOpen(false);
    }
  };

  const widthStyle =
    width === 'auto'
      ? 'min-w-[180px]'
      : width === 'trigger'
      ? 'min-w-full'
      : `min-w-[${width}px]`;

  return (
    <div ref={dropdownRef} className={cn('relative inline-block', className)}>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="inline-flex items-center"
        aria-expanded={isOpen}
        aria-haspopup="true"
      >
        {trigger}
      </button>

      {isOpen && (
        <div
          className={cn(
            'absolute z-50 mt-2 py-1 bg-white dark:bg-dark-800 rounded-lg shadow-lg border border-gray-200 dark:border-dark-700',
            widthStyle,
            align === 'left' ? 'left-0' : 'right-0'
          )}
          role="menu"
        >
          {items.map((item) =>
            item.divider ? (
              <hr
                key={item.id}
                className="my-1 border-gray-200 dark:border-dark-700"
              />
            ) : (
              <button
                key={item.id}
                type="button"
                onClick={() => handleItemClick(item)}
                disabled={item.disabled}
                className={cn(
                  'w-full px-4 py-2 text-sm text-left flex items-center gap-2 transition-colors',
                  item.disabled
                    ? 'text-gray-400 cursor-not-allowed'
                    : item.danger
                    ? 'text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-900/20'
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-700'
                )}
                role="menuitem"
              >
                {item.icon && <span className="w-5">{item.icon}</span>}
                {item.label}
              </button>
            )
          )}
        </div>
      )}
    </div>
  );
};

// Simple dropdown button with icon
export interface DropdownButtonProps {
  label: string;
  items: DropdownItem[];
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  align?: 'left' | 'right';
  className?: string;
}

export const DropdownButton: React.FC<DropdownButtonProps> = ({
  label,
  items,
  variant = 'secondary',
  size = 'md',
  align = 'left',
  className,
}) => {
  const variantStyles = {
    primary: 'bg-primary-600 text-white hover:bg-primary-700',
    secondary: 'bg-gray-100 text-gray-900 hover:bg-gray-200 dark:bg-dark-700 dark:text-white dark:hover:bg-dark-600',
    outline: 'border border-gray-300 text-gray-700 hover:bg-gray-50 dark:border-dark-600 dark:text-gray-300 dark:hover:bg-dark-800',
    ghost: 'text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-dark-700',
  };

  const sizeStyles = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-3 text-base',
  };

  return (
    <Dropdown
      align={align}
      items={items}
      trigger={
        <span
          className={cn(
            'inline-flex items-center gap-2 rounded-lg font-medium transition-colors',
            variantStyles[variant],
            sizeStyles[size],
            className
          )}
        >
          {label}
          <FiChevronDown className="h-4 w-4" />
        </span>
      }
    />
  );
};

export default Dropdown;
