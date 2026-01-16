/**
 * GeofenceDrawer Component - Geofence Creation Tool
 * Apollo Platform - Geolocation Frontend
 *
 * Provides UI for creating and editing geofence zones with
 * interactive map drawing.
 */

import React, { useState, useCallback } from 'react';
import { cn } from '../../utils/cn';
import LocationSearch from './LocationSearch';

interface GeofenceFormData {
  name: string;
  latitude: number;
  longitude: number;
  radius_meters: number;
  priority: 'low' | 'medium' | 'high' | 'critical';
  alert_on: ('entry' | 'exit' | 'loitering')[];
  case_id?: string;
}

interface GeofenceDrawerProps {
  /** Callback when geofence is created */
  onSubmit: (data: GeofenceFormData) => void;
  /** Callback to cancel */
  onCancel: () => void;
  /** Pre-fill with existing case ID */
  caseId?: string;
  /** Pre-fill with coordinates */
  initialCoordinates?: { lat: number; lng: number };
  /** Custom class name */
  className?: string;
  /** Is creating */
  isLoading?: boolean;
}

export const GeofenceDrawer: React.FC<GeofenceDrawerProps> = ({
  onSubmit,
  onCancel,
  caseId,
  initialCoordinates,
  className,
  isLoading = false,
}) => {
  const [formData, setFormData] = useState<GeofenceFormData>({
    name: '',
    latitude: initialCoordinates?.lat || 0,
    longitude: initialCoordinates?.lng || 0,
    radius_meters: 500,
    priority: 'medium',
    alert_on: ['entry', 'exit'],
    case_id: caseId,
  });

  const [errors, setErrors] = useState<Partial<Record<keyof GeofenceFormData, string>>>({});

  // Handle location selection from search
  const handleLocationSelect = useCallback((suggest: any) => {
    if (suggest.location) {
      setFormData((prev) => ({
        ...prev,
        latitude: suggest.location.lat,
        longitude: suggest.location.lng,
      }));
      setErrors((prev) => ({ ...prev, latitude: undefined, longitude: undefined }));
    }
  }, []);

  // Handle input changes
  const handleInputChange = useCallback((field: keyof GeofenceFormData, value: any) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    setErrors((prev) => ({ ...prev, [field]: undefined }));
  }, []);

  // Handle alert_on toggle
  const handleAlertToggle = useCallback((alertType: 'entry' | 'exit' | 'loitering') => {
    setFormData((prev) => {
      const current = prev.alert_on;
      if (current.includes(alertType)) {
        return { ...prev, alert_on: current.filter((a) => a !== alertType) };
      } else {
        return { ...prev, alert_on: [...current, alertType] };
      }
    });
  }, []);

  // Validate form
  const validate = useCallback((): boolean => {
    const newErrors: Partial<Record<keyof GeofenceFormData, string>> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
    }

    if (!formData.latitude || formData.latitude < -90 || formData.latitude > 90) {
      newErrors.latitude = 'Valid latitude is required';
    }

    if (!formData.longitude || formData.longitude < -180 || formData.longitude > 180) {
      newErrors.longitude = 'Valid longitude is required';
    }

    if (!formData.radius_meters || formData.radius_meters < 10 || formData.radius_meters > 100000) {
      newErrors.radius_meters = 'Radius must be between 10 and 100,000 meters';
    }

    if (formData.alert_on.length === 0) {
      newErrors.alert_on = 'Select at least one alert trigger';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  }, [formData]);

  // Handle submit
  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (validate()) {
        onSubmit(formData);
      }
    },
    [formData, validate, onSubmit]
  );

  // Preset radius options
  const radiusPresets = [
    { label: '100m', value: 100 },
    { label: '250m', value: 250 },
    { label: '500m', value: 500 },
    { label: '1km', value: 1000 },
    { label: '5km', value: 5000 },
    { label: '10km', value: 10000 },
  ];

  return (
    <div className={cn('bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6', className)}>
      <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
        Create Geofence Zone
      </h2>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Name */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Zone Name <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => handleInputChange('name', e.target.value)}
            placeholder="e.g., Victim Home Protection Zone"
            className={cn(
              'w-full px-3 py-2 border rounded-lg',
              'bg-white dark:bg-gray-700',
              'text-gray-900 dark:text-gray-100',
              errors.name ? 'border-red-500' : 'border-gray-300 dark:border-gray-600',
              'focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
            )}
          />
          {errors.name && <p className="mt-1 text-sm text-red-500">{errors.name}</p>}
        </div>

        {/* Location Search */}
        <LocationSearch
          label="Center Location"
          required
          placeholder="Search for location..."
          onSelect={handleLocationSelect}
          error={errors.latitude || errors.longitude}
          helperText="Search for a location or enter coordinates below"
        />

        {/* Coordinates */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Latitude <span className="text-red-500">*</span>
            </label>
            <input
              type="number"
              step="0.000001"
              value={formData.latitude || ''}
              onChange={(e) => handleInputChange('latitude', parseFloat(e.target.value))}
              placeholder="-90 to 90"
              className={cn(
                'w-full px-3 py-2 border rounded-lg',
                'bg-white dark:bg-gray-700',
                'text-gray-900 dark:text-gray-100',
                errors.latitude ? 'border-red-500' : 'border-gray-300 dark:border-gray-600',
                'focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
              )}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Longitude <span className="text-red-500">*</span>
            </label>
            <input
              type="number"
              step="0.000001"
              value={formData.longitude || ''}
              onChange={(e) => handleInputChange('longitude', parseFloat(e.target.value))}
              placeholder="-180 to 180"
              className={cn(
                'w-full px-3 py-2 border rounded-lg',
                'bg-white dark:bg-gray-700',
                'text-gray-900 dark:text-gray-100',
                errors.longitude ? 'border-red-500' : 'border-gray-300 dark:border-gray-600',
                'focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
              )}
            />
          </div>
        </div>

        {/* Radius */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Radius (meters) <span className="text-red-500">*</span>
          </label>

          {/* Preset buttons */}
          <div className="flex flex-wrap gap-2 mb-2">
            {radiusPresets.map((preset) => (
              <button
                key={preset.value}
                type="button"
                onClick={() => handleInputChange('radius_meters', preset.value)}
                className={cn(
                  'px-3 py-1 text-sm rounded-full border',
                  formData.radius_meters === preset.value
                    ? 'bg-blue-500 text-white border-blue-500'
                    : 'bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-600'
                )}
              >
                {preset.label}
              </button>
            ))}
          </div>

          {/* Custom input */}
          <input
            type="number"
            value={formData.radius_meters}
            onChange={(e) => handleInputChange('radius_meters', parseInt(e.target.value))}
            min={10}
            max={100000}
            className={cn(
              'w-full px-3 py-2 border rounded-lg',
              'bg-white dark:bg-gray-700',
              'text-gray-900 dark:text-gray-100',
              errors.radius_meters ? 'border-red-500' : 'border-gray-300 dark:border-gray-600',
              'focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
            )}
          />
          {errors.radius_meters && <p className="mt-1 text-sm text-red-500">{errors.radius_meters}</p>}
        </div>

        {/* Priority */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Alert Priority
          </label>
          <select
            value={formData.priority}
            onChange={(e) => handleInputChange('priority', e.target.value)}
            className={cn(
              'w-full px-3 py-2 border rounded-lg',
              'bg-white dark:bg-gray-700',
              'text-gray-900 dark:text-gray-100',
              'border-gray-300 dark:border-gray-600',
              'focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
            )}
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        {/* Alert Triggers */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Alert Triggers <span className="text-red-500">*</span>
          </label>
          <div className="space-y-2">
            {[
              { value: 'entry' as const, label: 'Entry', description: 'Alert when device enters zone' },
              { value: 'exit' as const, label: 'Exit', description: 'Alert when device leaves zone' },
              { value: 'loitering' as const, label: 'Loitering', description: 'Alert when device stays in zone for extended time' },
            ].map((alert) => (
              <label
                key={alert.value}
                className={cn(
                  'flex items-start p-3 rounded-lg border cursor-pointer',
                  formData.alert_on.includes(alert.value)
                    ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-500'
                    : 'bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'
                )}
              >
                <input
                  type="checkbox"
                  checked={formData.alert_on.includes(alert.value)}
                  onChange={() => handleAlertToggle(alert.value)}
                  className="mt-1 h-4 w-4 text-blue-500 rounded"
                />
                <div className="ml-3">
                  <span className="block text-sm font-medium text-gray-900 dark:text-gray-100">
                    {alert.label}
                  </span>
                  <span className="block text-xs text-gray-500 dark:text-gray-400">
                    {alert.description}
                  </span>
                </div>
              </label>
            ))}
          </div>
          {errors.alert_on && <p className="mt-1 text-sm text-red-500">{errors.alert_on}</p>}
        </div>

        {/* Case ID */}
        {!caseId && (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Case ID (optional)
            </label>
            <input
              type="text"
              value={formData.case_id || ''}
              onChange={(e) => handleInputChange('case_id', e.target.value)}
              placeholder="e.g., CASE-2026-001"
              className={cn(
                'w-full px-3 py-2 border rounded-lg',
                'bg-white dark:bg-gray-700',
                'text-gray-900 dark:text-gray-100',
                'border-gray-300 dark:border-gray-600',
                'focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
              )}
            />
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3 pt-4">
          <button
            type="button"
            onClick={onCancel}
            className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isLoading}
            className={cn(
              'flex-1 px-4 py-2 rounded-lg text-white transition-colors',
              'bg-blue-500 hover:bg-blue-600',
              'disabled:opacity-50 disabled:cursor-not-allowed'
            )}
          >
            {isLoading ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Creating...
              </span>
            ) : (
              'Create Geofence'
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

export default GeofenceDrawer;
