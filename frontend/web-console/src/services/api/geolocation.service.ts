/**
 * Geolocation API Service
 * Apollo Platform - Geolocation Frontend
 *
 * Provides API client functions for the GEOINT tracking backend.
 */

import apiClient from './client';

// ==================== Types ====================

export interface TrackedDevice {
  device_id: string;
  device_name: string;
  target_description: string;
  case_id: string;
  status: 'active' | 'inactive' | 'offline' | 'low_battery';
  created_at: string;
  last_update: string | null;
  battery_level: number;
}

export interface RegisterDeviceRequest {
  device_name: string;
  target_description: string;
  case_id: string;
  authorization: string;
  warrant_expiration?: string;
  authorized_by?: string;
  update_interval?: number;
  metadata?: Record<string, any>;
}

export interface LocationUpdate {
  device_id: string;
  latitude: number;
  longitude: number;
  altitude: number;
  speed: number;
  heading: number;
  accuracy: number;
  battery_level: number;
  signal_strength: number;
  timestamp: string;
}

export interface LocationUpdateRequest {
  latitude: number;
  longitude: number;
  altitude?: number;
  speed?: number;
  heading?: number;
  accuracy?: number;
  battery_level?: number;
  signal_strength?: number;
  metadata?: Record<string, any>;
}

export interface Geofence {
  geofence_id: string;
  name: string;
  center_latitude: number;
  center_longitude: number;
  radius_meters: number;
  priority: 'low' | 'medium' | 'high' | 'critical';
  active: boolean;
  created_at: string;
}

export interface CreateGeofenceRequest {
  name: string;
  latitude: number;
  longitude: number;
  radius_meters: number;
  alert_on?: ('entry' | 'exit' | 'loitering')[];
  priority?: 'low' | 'medium' | 'high' | 'critical';
  case_id?: string;
  metadata?: Record<string, any>;
}

export interface GeofenceAlert {
  alert_id: string;
  geofence_id: string;
  geofence_name: string;
  device_id: string;
  event_type: string;
  latitude: number;
  longitude: number;
  priority: string;
  timestamp: string;
  acknowledged: boolean;
}

export interface MovementPattern {
  pattern_id: string;
  device_id: string;
  analysis_period: string;
  frequent_locations: FrequentLocation[];
  home_location: PredictedLocation | null;
  work_location: PredictedLocation | null;
  average_daily_distance_km: number;
  confidence_score: number;
}

export interface FrequentLocation {
  latitude: number;
  longitude: number;
  visit_count: number;
  most_common_hour: number | null;
}

export interface PredictedLocation {
  latitude: number;
  longitude: number;
  confidence: number;
  label: string;
}

export interface MovementStatistics {
  total_points: number;
  avg_speed: number | null;
  max_speed: number | null;
  avg_accuracy: number | null;
  min_battery: number | null;
  avg_battery: number | null;
  min_lat: number | null;
  max_lat: number | null;
  min_lon: number | null;
  max_lon: number | null;
  total_distance_meters: number;
  total_distance_km: number;
  time_span_hours: number;
}

export interface ColocationResult {
  colocations: ColocationEvent[];
  total_events: number;
  analysis_timeframe_hours: number;
}

export interface ColocationEvent {
  device_a: string;
  device_b: string;
  timestamp: string;
  location: {
    latitude: number;
    longitude: number;
  };
  distance_meters: number;
  significance: string;
}

// ==================== API Service ====================

const BASE_URL = '/api/geoint';

export const geolocationService = {
  // ==================== Device Operations ====================

  /**
   * Register a new tracking device
   */
  async registerDevice(request: RegisterDeviceRequest): Promise<TrackedDevice> {
    const response = await apiClient.post<TrackedDevice>(`${BASE_URL}/devices`, request);
    return response.data;
  },

  /**
   * Get all devices
   */
  async getDevices(caseId?: string): Promise<TrackedDevice[]> {
    const params = caseId ? { case_id: caseId } : {};
    const response = await apiClient.get<TrackedDevice[]>(`${BASE_URL}/devices`, { params });
    return response.data;
  },

  /**
   * Get device by ID
   */
  async getDevice(deviceId: string): Promise<TrackedDevice> {
    const response = await apiClient.get<TrackedDevice>(`${BASE_URL}/devices/${deviceId}`);
    return response.data;
  },

  /**
   * Deactivate a device
   */
  async deactivateDevice(deviceId: string, reason?: string): Promise<void> {
    await apiClient.delete(`${BASE_URL}/devices/${deviceId}`, {
      params: { reason },
    });
  },

  // ==================== Location Operations ====================

  /**
   * Update device location
   */
  async updateLocation(deviceId: string, location: LocationUpdateRequest): Promise<LocationUpdate> {
    const response = await apiClient.post<LocationUpdate>(
      `${BASE_URL}/devices/${deviceId}/location`,
      location
    );
    return response.data;
  },

  /**
   * Get current location
   */
  async getCurrentLocation(deviceId: string): Promise<LocationUpdate> {
    const response = await apiClient.get<LocationUpdate>(`${BASE_URL}/devices/${deviceId}/location`);
    return response.data;
  },

  /**
   * Get location history
   */
  async getLocationHistory(
    deviceId: string,
    startDate?: string,
    endDate?: string,
    limit: number = 1000
  ): Promise<LocationUpdate[]> {
    const params: Record<string, any> = { limit };
    if (startDate) params.start_date = startDate;
    if (endDate) params.end_date = endDate;

    const response = await apiClient.get<LocationUpdate[]>(
      `${BASE_URL}/devices/${deviceId}/history`,
      { params }
    );
    return response.data;
  },

  // ==================== Geofence Operations ====================

  /**
   * Create a geofence
   */
  async createGeofence(request: CreateGeofenceRequest): Promise<Geofence> {
    const response = await apiClient.post<Geofence>(`${BASE_URL}/geofences`, request);
    return response.data;
  },

  /**
   * Get all geofences
   */
  async getGeofences(caseId?: string): Promise<Geofence[]> {
    const params = caseId ? { case_id: caseId } : {};
    const response = await apiClient.get<Geofence[]>(`${BASE_URL}/geofences`, { params });
    return response.data;
  },

  /**
   * Get geofence by ID
   */
  async getGeofence(geofenceId: string): Promise<Geofence> {
    const response = await apiClient.get<Geofence>(`${BASE_URL}/geofences/${geofenceId}`);
    return response.data;
  },

  /**
   * Update a geofence
   */
  async updateGeofence(geofenceId: string, updates: Partial<Geofence>): Promise<void> {
    await apiClient.put(`${BASE_URL}/geofences/${geofenceId}`, null, {
      params: updates,
    });
  },

  /**
   * Delete a geofence
   */
  async deleteGeofence(geofenceId: string): Promise<void> {
    await apiClient.delete(`${BASE_URL}/geofences/${geofenceId}`);
  },

  /**
   * Assign geofence to device
   */
  async assignGeofenceToDevice(geofenceId: string, deviceId: string): Promise<void> {
    await apiClient.post(`${BASE_URL}/geofences/${geofenceId}/assign/${deviceId}`);
  },

  // ==================== Alert Operations ====================

  /**
   * Get alerts
   */
  async getAlerts(
    deviceId?: string,
    geofenceId?: string,
    acknowledged?: boolean,
    limit: number = 100
  ): Promise<GeofenceAlert[]> {
    const params: Record<string, any> = { limit };
    if (deviceId) params.device_id = deviceId;
    if (geofenceId) params.geofence_id = geofenceId;
    if (acknowledged !== undefined) params.acknowledged = acknowledged;

    const response = await apiClient.get<GeofenceAlert[]>(`${BASE_URL}/alerts`, { params });
    return response.data;
  },

  /**
   * Acknowledge an alert
   */
  async acknowledgeAlert(alertId: string): Promise<void> {
    await apiClient.post(`${BASE_URL}/alerts/${alertId}/acknowledge`);
  },

  /**
   * Get unacknowledged alert count
   */
  async getUnacknowledgedCount(deviceId?: string): Promise<number> {
    const params = deviceId ? { device_id: deviceId } : {};
    const response = await apiClient.get<{ count: number }>(
      `${BASE_URL}/alerts/unacknowledged/count`,
      { params }
    );
    return response.data.count;
  },

  // ==================== Analysis Operations ====================

  /**
   * Analyze movement patterns
   */
  async analyzeMovementPatterns(deviceId: string, days: number = 30): Promise<MovementPattern> {
    const response = await apiClient.get<MovementPattern>(
      `${BASE_URL}/devices/${deviceId}/patterns`,
      { params: { days } }
    );
    return response.data;
  },

  /**
   * Detect co-location
   */
  async detectColocation(
    deviceIds: string[],
    distanceThreshold: number = 100,
    durationThreshold: number = 300,
    timeframeHours: number = 24
  ): Promise<ColocationResult> {
    const response = await apiClient.post<ColocationResult>(`${BASE_URL}/analysis/colocation`, {
      device_ids: deviceIds,
      distance_threshold_meters: distanceThreshold,
      duration_threshold_seconds: durationThreshold,
      timeframe_hours: timeframeHours,
    });
    return response.data;
  },

  /**
   * Get movement statistics
   */
  async getMovementStatistics(
    deviceId: string,
    startDate: string,
    endDate: string
  ): Promise<MovementStatistics> {
    const response = await apiClient.get<MovementStatistics>(
      `${BASE_URL}/devices/${deviceId}/statistics`,
      { params: { start_date: startDate, end_date: endDate } }
    );
    return response.data;
  },

  /**
   * Get frequent locations
   */
  async getFrequentLocations(
    deviceId: string,
    startDate: string,
    endDate: string,
    minVisits: number = 5
  ): Promise<FrequentLocation[]> {
    const response = await apiClient.get<{ frequent_locations: FrequentLocation[] }>(
      `${BASE_URL}/devices/${deviceId}/frequent-locations`,
      { params: { start_date: startDate, end_date: endDate, min_visits: minVisits } }
    );
    return response.data.frequent_locations;
  },

  // ==================== Export Operations ====================

  /**
   * Export tracking data
   */
  async exportTrackingData(
    deviceId: string,
    format: 'json' | 'kml' = 'json',
    startDate?: string,
    endDate?: string
  ): Promise<Blob> {
    const params: Record<string, any> = { format };
    if (startDate) params.start_date = startDate;
    if (endDate) params.end_date = endDate;

    const response = await apiClient.get(`${BASE_URL}/devices/${deviceId}/export`, {
      params,
      responseType: 'blob',
    });
    return response.data;
  },

  // ==================== Health ====================

  /**
   * Check service health
   */
  async checkHealth(): Promise<{
    status: string;
    database: string;
    active_devices: number;
    active_geofences: number;
    pending_alerts: number;
  }> {
    const response = await apiClient.get(`${BASE_URL}/health`);
    return response.data;
  },
};

export default geolocationService;
