import React from 'react';
import { cn } from '@utils/cn';

export interface FormGroupProps extends React.HTMLAttributes<HTMLDivElement> {
  label?: string;
  htmlFor?: string;
  error?: string;
  hint?: string;
  required?: boolean;
  inline?: boolean;
}

export const FormGroup: React.FC<FormGroupProps> = ({
  children,
  label,
  htmlFor,
  error,
  hint,
  required = false,
  inline = false,
  className,
  ...props
}) => {
  return (
    <div className={cn('w-full', className)} {...props}>
      {label && (
        <label
          htmlFor={htmlFor}
          className={cn(
            'block mb-2 text-sm font-medium text-gray-700 dark:text-gray-300',
            inline && 'inline-block mr-4'
          )}
        >
          {label}
          {required && <span className="text-danger-500 ml-1">*</span>}
        </label>
      )}
      {children}
      {error && (
        <p className="mt-1 text-sm text-danger-600 dark:text-danger-400">{error}</p>
      )}
      {hint && !error && (
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{hint}</p>
      )}
    </div>
  );
};

export default FormGroup;
