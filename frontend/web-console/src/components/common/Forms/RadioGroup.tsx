import React from 'react';
import { cn } from '@utils/cn';

export interface RadioOption {
  value: string;
  label: string;
  description?: string;
  disabled?: boolean;
}

export interface RadioGroupProps {
  name: string;
  options: RadioOption[];
  value?: string;
  onChange?: (value: string) => void;
  error?: string;
  orientation?: 'horizontal' | 'vertical';
  className?: string;
}

export const RadioGroup: React.FC<RadioGroupProps> = ({
  name,
  options,
  value,
  onChange,
  error,
  orientation = 'vertical',
  className,
}) => {
  return (
    <div
      className={cn(
        'space-y-2',
        orientation === 'horizontal' && 'flex flex-wrap gap-4 space-y-0',
        className
      )}
      role="radiogroup"
    >
      {options.map((option) => (
        <label
          key={option.value}
          className={cn(
            'flex items-start cursor-pointer',
            option.disabled && 'opacity-50 cursor-not-allowed'
          )}
        >
          <input
            type="radio"
            name={name}
            value={option.value}
            checked={value === option.value}
            onChange={(e) => onChange?.(e.target.value)}
            disabled={option.disabled}
            className={cn(
              'h-4 w-4 text-primary-600 border-gray-300 focus:ring-primary-500 mt-0.5',
              error && 'border-danger-500'
            )}
          />
          <div className="ml-3">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              {option.label}
            </span>
            {option.description && (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {option.description}
              </p>
            )}
          </div>
        </label>
      ))}
      {error && (
        <p className="text-sm text-danger-600 dark:text-danger-400">{error}</p>
      )}
    </div>
  );
};

export default RadioGroup;
