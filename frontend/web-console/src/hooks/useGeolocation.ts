/**
 * useGeolocation Hook - Geolocation State Management
 * Apollo Platform - Geolocation Frontend
 *
 * Provides hooks for tracking devices, geofences, and real-time location updates.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { geolocationService, TrackedDevice, Geofence, LocationUpdate, GeofenceAlert } from '../services/api/geolocation.service';

// ==================== useDevices Hook ====================
export interface UseDevicesOptions {
  caseId?: string;
  enabled?: boolean;
  refetchInterval?: number;
}

export function useDevices(options: UseDevicesOptions = {}) {
  const { caseId, enabled = true, refetchInterval } = options;
  const queryClient = useQueryClient();

  const {
    data: devices,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['geoint-devices', caseId],
    queryFn: () => geolocationService.getDevices(caseId),
    enabled,
    refetchInterval,
  });

  const registerMutation = useMutation({
    mutationFn: geolocationService.registerDevice,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['geoint-devices'] });
    },
  });

  const deactivateMutation = useMutation({
    mutationFn: ({ deviceId, reason }: { deviceId: string; reason?: string }) =>
      geolocationService.deactivateDevice(deviceId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['geoint-devices'] });
    },
  });

  return {
    devices: devices || [],
    isLoading,
    error,
    refetch,
    registerDevice: registerMutation.mutateAsync,
    isRegistering: registerMutation.isPending,
    deactivateDevice: deactivateMutation.mutateAsync,
    isDeactivating: deactivateMutation.isPending,
  };
}

// ==================== useDevice Hook ====================
export function useDevice(deviceId: string) {
  const queryClient = useQueryClient();

  const {
    data: device,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['geoint-device', deviceId],
    queryFn: () => geolocationService.getDevice(deviceId),
    enabled: !!deviceId,
  });

  const {
    data: currentLocation,
    refetch: refetchLocation,
  } = useQuery({
    queryKey: ['geoint-device-location', deviceId],
    queryFn: () => geolocationService.getCurrentLocation(deviceId),
    enabled: !!deviceId,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const updateLocationMutation = useMutation({
    mutationFn: (location: Omit<LocationUpdate, 'device_id' | 'timestamp'>) =>
      geolocationService.updateLocation(deviceId, location),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['geoint-device-location', deviceId] });
    },
  });

  return {
    device,
    currentLocation,
    isLoading,
    error,
    updateLocation: updateLocationMutation.mutateAsync,
    isUpdating: updateLocationMutation.isPending,
    refetchLocation,
  };
}

// ==================== useLocationHistory Hook ====================
export interface UseLocationHistoryOptions {
  deviceId: string;
  startDate?: string;
  endDate?: string;
  limit?: number;
  enabled?: boolean;
}

export function useLocationHistory(options: UseLocationHistoryOptions) {
  const { deviceId, startDate, endDate, limit = 1000, enabled = true } = options;

  const {
    data: history,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['geoint-location-history', deviceId, startDate, endDate, limit],
    queryFn: () => geolocationService.getLocationHistory(deviceId, startDate, endDate, limit),
    enabled: enabled && !!deviceId,
  });

  // Convert to path format for map
  const trackPath = history
    ? {
        device_id: deviceId,
        points: history.map((loc) => ({ lat: loc.latitude, lng: loc.longitude })),
      }
    : null;

  return {
    history: history || [],
    trackPath,
    isLoading,
    error,
    refetch,
  };
}

// ==================== useGeofences Hook ====================
export interface UseGeofencesOptions {
  caseId?: string;
  enabled?: boolean;
}

export function useGeofences(options: UseGeofencesOptions = {}) {
  const { caseId, enabled = true } = options;
  const queryClient = useQueryClient();

  const {
    data: geofences,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['geoint-geofences', caseId],
    queryFn: () => geolocationService.getGeofences(caseId),
    enabled,
  });

  const createMutation = useMutation({
    mutationFn: geolocationService.createGeofence,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['geoint-geofences'] });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ geofenceId, updates }: { geofenceId: string; updates: Partial<Geofence> }) =>
      geolocationService.updateGeofence(geofenceId, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['geoint-geofences'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: geolocationService.deleteGeofence,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['geoint-geofences'] });
    },
  });

  const assignMutation = useMutation({
    mutationFn: ({ geofenceId, deviceId }: { geofenceId: string; deviceId: string }) =>
      geolocationService.assignGeofenceToDevice(geofenceId, deviceId),
  });

  return {
    geofences: geofences || [],
    isLoading,
    error,
    refetch,
    createGeofence: createMutation.mutateAsync,
    isCreating: createMutation.isPending,
    updateGeofence: updateMutation.mutateAsync,
    isUpdating: updateMutation.isPending,
    deleteGeofence: deleteMutation.mutateAsync,
    isDeleting: deleteMutation.isPending,
    assignGeofence: assignMutation.mutateAsync,
  };
}

// ==================== useAlerts Hook ====================
export interface UseAlertsOptions {
  deviceId?: string;
  geofenceId?: string;
  acknowledged?: boolean;
  limit?: number;
  enabled?: boolean;
  refetchInterval?: number;
}

export function useAlerts(options: UseAlertsOptions = {}) {
  const { deviceId, geofenceId, acknowledged, limit = 100, enabled = true, refetchInterval = 10000 } = options;
  const queryClient = useQueryClient();

  const {
    data: alerts,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['geoint-alerts', deviceId, geofenceId, acknowledged, limit],
    queryFn: () => geolocationService.getAlerts(deviceId, geofenceId, acknowledged, limit),
    enabled,
    refetchInterval,
  });

  const acknowledgeMutation = useMutation({
    mutationFn: geolocationService.acknowledgeAlert,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['geoint-alerts'] });
    },
  });

  const unacknowledgedCount = alerts?.filter((a) => !a.acknowledged).length || 0;

  return {
    alerts: alerts || [],
    unacknowledgedCount,
    isLoading,
    error,
    refetch,
    acknowledgeAlert: acknowledgeMutation.mutateAsync,
    isAcknowledging: acknowledgeMutation.isPending,
  };
}

// ==================== useMovementPatterns Hook ====================
export function useMovementPatterns(deviceId: string, days: number = 30) {
  const {
    data: patterns,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['geoint-patterns', deviceId, days],
    queryFn: () => geolocationService.analyzeMovementPatterns(deviceId, days),
    enabled: !!deviceId,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  });

  return {
    patterns,
    isLoading,
    error,
    refetch,
  };
}

// ==================== useRealTimeTracking Hook ====================
export interface UseRealTimeTrackingOptions {
  deviceId: string;
  enabled?: boolean;
  onLocationUpdate?: (location: LocationUpdate) => void;
  onAlert?: (alert: GeofenceAlert) => void;
}

export function useRealTimeTracking(options: UseRealTimeTrackingOptions) {
  const { deviceId, enabled = true, onLocationUpdate, onAlert } = options;
  const [isConnected, setIsConnected] = useState(false);
  const [lastLocation, setLastLocation] = useState<LocationUpdate | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<GeofenceAlert[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!enabled || !deviceId) return;

    const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/geoint/location/${deviceId}`;

    try {
      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onopen = () => {
        setIsConnected(true);
        console.log(`WebSocket connected for device ${deviceId}`);
      };

      wsRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === 'location_update') {
            const location: LocationUpdate = {
              device_id: data.device_id,
              latitude: data.latitude,
              longitude: data.longitude,
              speed: data.speed,
              heading: data.heading,
              timestamp: data.timestamp,
              altitude: 0,
              accuracy: 10,
              battery_level: 100,
              signal_strength: 100,
            };
            setLastLocation(location);
            onLocationUpdate?.(location);
          }

          if (data.type === 'geofence_alert') {
            const alert: GeofenceAlert = {
              alert_id: data.alert_id,
              geofence_id: data.geofence_id,
              geofence_name: data.geofence_name || '',
              device_id: deviceId,
              event_type: data.event_type,
              latitude: data.latitude || 0,
              longitude: data.longitude || 0,
              priority: data.priority,
              timestamp: data.timestamp,
              acknowledged: false,
            };
            setRecentAlerts((prev) => [alert, ...prev].slice(0, 10));
            onAlert?.(alert);
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e);
        }
      };

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        setIsConnected(false);
      };

      wsRef.current.onclose = () => {
        setIsConnected(false);
        console.log(`WebSocket closed for device ${deviceId}`);
      };

      // Ping to keep alive
      const pingInterval = setInterval(() => {
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send('ping');
        }
      }, 30000);

      return () => {
        clearInterval(pingInterval);
        wsRef.current?.close();
      };
    } catch (error) {
      console.error('Failed to create WebSocket:', error);
    }
  }, [deviceId, enabled, onLocationUpdate, onAlert]);

  return {
    isConnected,
    lastLocation,
    recentAlerts,
  };
}

// ==================== useColocationDetection Hook ====================
export function useColocationDetection() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<any>(null);

  const detectColocation = useCallback(
    async (
      deviceIds: string[],
      distanceThreshold: number = 100,
      durationThreshold: number = 300,
      timeframeHours: number = 24
    ) => {
      setIsAnalyzing(true);
      try {
        const data = await geolocationService.detectColocation(
          deviceIds,
          distanceThreshold,
          durationThreshold,
          timeframeHours
        );
        setResults(data);
        return data;
      } finally {
        setIsAnalyzing(false);
      }
    },
    []
  );

  return {
    detectColocation,
    isAnalyzing,
    results,
  };
}

// ==================== useGeolocationStats Hook ====================
export function useGeolocationStats(deviceId: string, startDate: string, endDate: string) {
  const {
    data: stats,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['geoint-stats', deviceId, startDate, endDate],
    queryFn: () => geolocationService.getMovementStatistics(deviceId, startDate, endDate),
    enabled: !!deviceId && !!startDate && !!endDate,
  });

  return {
    stats,
    isLoading,
    error,
  };
}
