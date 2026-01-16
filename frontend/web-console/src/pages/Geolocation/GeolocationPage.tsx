/**
 * GeolocationPage - Main GEOINT Tracking Dashboard
 * Apollo Platform - Geolocation Frontend
 *
 * Central hub for GPS tracking, geofencing, and location analysis.
 */

import React, { useState, useCallback } from 'react';
import { cn } from '../../utils/cn';
import TrackingMap from '../../components/geolocation/TrackingMap';
import LocationSearch from '../../components/geolocation/LocationSearch';
import GeofenceDrawer from '../../components/geolocation/GeofenceDrawer';
import {
  useDevices,
  useGeofences,
  useAlerts,
  useMovementPatterns,
  useRealTimeTracking,
  useLocationHistory,
} from '../../hooks/useGeolocation';
import { TrackedDevice, Geofence, GeofenceAlert } from '../../services/api/geolocation.service';

// Tab type
type TabType = 'devices' | 'geofences' | 'alerts' | 'analysis';

const GeolocationPage: React.FC = () => {
  // State
  const [activeTab, setActiveTab] = useState<TabType>('devices');
  const [selectedDevice, setSelectedDevice] = useState<TrackedDevice | null>(null);
  const [showGeofenceForm, setShowGeofenceForm] = useState(false);
  const [searchedLocation, setSearchedLocation] = useState<{ lat: number; lng: number } | null>(null);

  // Hooks
  const { devices, isLoading: devicesLoading, registerDevice, isRegistering } = useDevices({
    refetchInterval: 30000,
  });

  const { geofences, isLoading: geofencesLoading, createGeofence, isCreating } = useGeofences();

  const { alerts, unacknowledgedCount, acknowledgeAlert, isAcknowledging } = useAlerts({
    refetchInterval: 10000,
  });

  const { history: locationHistory, trackPath } = useLocationHistory({
    deviceId: selectedDevice?.device_id || '',
    limit: 500,
    enabled: !!selectedDevice,
  });

  const { patterns } = useMovementPatterns(selectedDevice?.device_id || '', 30);

  // Real-time tracking for selected device
  const { lastLocation, recentAlerts } = useRealTimeTracking({
    deviceId: selectedDevice?.device_id || '',
    enabled: !!selectedDevice,
  });

  // Handle location search
  const handleLocationSearch = useCallback((suggest: any) => {
    if (suggest.location) {
      setSearchedLocation({
        lat: suggest.location.lat,
        lng: suggest.location.lng,
      });
    }
  }, []);

  // Handle geofence creation
  const handleCreateGeofence = useCallback(
    async (data: any) => {
      await createGeofence(data);
      setShowGeofenceForm(false);
    },
    [createGeofence]
  );

  // Handle device selection
  const handleDeviceClick = useCallback((device: TrackedDevice) => {
    setSelectedDevice(device);
    setActiveTab('analysis');
  }, []);

  // Handle geofence click
  const handleGeofenceClick = useCallback((geofence: Geofence) => {
    setActiveTab('geofences');
  }, []);

  // Get map points for analysis
  const analysisPoints = patterns
    ? [
        ...(patterns.home_location
          ? [
              {
                latitude: patterns.home_location.latitude,
                longitude: patterns.home_location.longitude,
                type: 'home' as const,
                label: 'Home Location',
              },
            ]
          : []),
        ...(patterns.work_location
          ? [
              {
                latitude: patterns.work_location.latitude,
                longitude: patterns.work_location.longitude,
                type: 'work' as const,
                label: 'Work Location',
              },
            ]
          : []),
        ...patterns.frequent_locations.slice(0, 5).map((loc, idx) => ({
          latitude: loc.latitude,
          longitude: loc.longitude,
          type: 'point_of_interest' as const,
          label: `Frequent Location #${idx + 1}`,
        })),
      ]
    : [];

  // Format device for map
  const mapDevices = devices.map((d) => ({
    device_id: d.device_id,
    device_name: d.device_name,
    latitude: lastLocation?.device_id === d.device_id ? lastLocation.latitude : 0,
    longitude: lastLocation?.device_id === d.device_id ? lastLocation.longitude : 0,
    speed: lastLocation?.speed,
    heading: lastLocation?.heading,
    battery_level: d.battery_level,
    timestamp: d.last_update || undefined,
    status: d.status as 'active' | 'inactive' | 'offline',
  }));

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                GEOINT Tracking Center
              </h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Real-time GPS tracking and geofence monitoring
              </p>
            </div>

            {/* Quick Stats */}
            <div className="flex gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">{devices.length}</div>
                <div className="text-xs text-gray-500">Active Devices</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">{geofences.length}</div>
                <div className="text-xs text-gray-500">Geofences</div>
              </div>
              <div className="text-center">
                <div className={cn(
                  "text-2xl font-bold",
                  unacknowledgedCount > 0 ? "text-red-600" : "text-gray-400"
                )}>
                  {unacknowledgedCount}
                </div>
                <div className="text-xs text-gray-500">Pending Alerts</div>
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Map Section */}
          <div className="lg:col-span-2">
            {/* Search Bar */}
            <div className="mb-4">
              <LocationSearch
                placeholder="Search location to center map..."
                onSelect={handleLocationSearch}
                fixtures={[
                  { label: 'FBI Headquarters, Washington DC', location: { lat: 38.8977, lng: -77.0365 } },
                  { label: 'NYC Times Square', location: { lat: 40.7580, lng: -73.9855 } },
                ]}
              />
            </div>

            {/* Map */}
            <TrackingMap
              center={searchedLocation ? [searchedLocation.lat, searchedLocation.lng] : [40.7128, -74.006]}
              zoom={12}
              devices={mapDevices.filter(d => d.latitude && d.longitude)}
              geofences={geofences}
              points={analysisPoints}
              tracks={trackPath ? [{ ...trackPath, color: '#3b82f6' }] : []}
              onDeviceClick={(d) => {
                const device = devices.find(dev => dev.device_id === d.device_id);
                if (device) handleDeviceClick(device);
              }}
              onGeofenceClick={(g) => handleGeofenceClick(g as any)}
              height="500px"
              selectedDeviceId={selectedDevice?.device_id}
            />
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            {/* Tabs */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow mb-4">
              <div className="flex border-b border-gray-200 dark:border-gray-700">
                {(['devices', 'geofences', 'alerts', 'analysis'] as TabType[]).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={cn(
                      'flex-1 px-4 py-3 text-sm font-medium capitalize',
                      activeTab === tab
                        ? 'text-blue-600 border-b-2 border-blue-600'
                        : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
                    )}
                  >
                    {tab}
                    {tab === 'alerts' && unacknowledgedCount > 0 && (
                      <span className="ml-2 px-2 py-0.5 text-xs bg-red-500 text-white rounded-full">
                        {unacknowledgedCount}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Tab Content */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 max-h-[600px] overflow-y-auto">
              {/* Devices Tab */}
              {activeTab === 'devices' && (
                <div className="space-y-4">
                  <h3 className="font-semibold text-gray-900 dark:text-white">Tracked Devices</h3>
                  {devicesLoading ? (
                    <div className="text-center py-8 text-gray-500">Loading...</div>
                  ) : devices.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">No devices registered</div>
                  ) : (
                    <div className="space-y-2">
                      {devices.map((device) => (
                        <div
                          key={device.device_id}
                          onClick={() => handleDeviceClick(device)}
                          className={cn(
                            'p-3 rounded-lg border cursor-pointer transition-colors',
                            selectedDevice?.device_id === device.device_id
                              ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-500'
                              : 'bg-gray-50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700'
                          )}
                        >
                          <div className="flex justify-between items-start">
                            <div>
                              <h4 className="font-medium text-gray-900 dark:text-white">
                                {device.device_name}
                              </h4>
                              <p className="text-xs text-gray-500 dark:text-gray-400">
                                {device.target_description}
                              </p>
                            </div>
                            <span
                              className={cn(
                                'px-2 py-0.5 text-xs rounded-full',
                                device.status === 'active' && 'bg-green-100 text-green-800',
                                device.status === 'inactive' && 'bg-gray-100 text-gray-800',
                                device.status === 'offline' && 'bg-red-100 text-red-800',
                                device.status === 'low_battery' && 'bg-yellow-100 text-yellow-800'
                              )}
                            >
                              {device.status}
                            </span>
                          </div>
                          <div className="mt-2 flex items-center gap-4 text-xs text-gray-500">
                            <span>Battery: {device.battery_level}%</span>
                            {device.last_update && (
                              <span>
                                Updated: {new Date(device.last_update).toLocaleTimeString()}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Geofences Tab */}
              {activeTab === 'geofences' && (
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="font-semibold text-gray-900 dark:text-white">Geofence Zones</h3>
                    <button
                      onClick={() => setShowGeofenceForm(true)}
                      className="px-3 py-1.5 text-sm bg-blue-500 text-white rounded-lg hover:bg-blue-600"
                    >
                      + Add Zone
                    </button>
                  </div>

                  {showGeofenceForm ? (
                    <GeofenceDrawer
                      onSubmit={handleCreateGeofence}
                      onCancel={() => setShowGeofenceForm(false)}
                      isLoading={isCreating}
                      initialCoordinates={searchedLocation || undefined}
                    />
                  ) : geofencesLoading ? (
                    <div className="text-center py-8 text-gray-500">Loading...</div>
                  ) : geofences.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">No geofences created</div>
                  ) : (
                    <div className="space-y-2">
                      {geofences.map((geofence) => (
                        <div
                          key={geofence.geofence_id}
                          className="p-3 rounded-lg border bg-gray-50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600"
                        >
                          <div className="flex justify-between items-start">
                            <div>
                              <h4 className="font-medium text-gray-900 dark:text-white">
                                {geofence.name}
                              </h4>
                              <p className="text-xs text-gray-500 dark:text-gray-400">
                                Radius: {geofence.radius_meters}m
                              </p>
                            </div>
                            <span
                              className={cn(
                                'px-2 py-0.5 text-xs rounded-full',
                                geofence.priority === 'critical' && 'bg-red-100 text-red-800',
                                geofence.priority === 'high' && 'bg-orange-100 text-orange-800',
                                geofence.priority === 'medium' && 'bg-yellow-100 text-yellow-800',
                                geofence.priority === 'low' && 'bg-green-100 text-green-800'
                              )}
                            >
                              {geofence.priority}
                            </span>
                          </div>
                          <div className="mt-2 text-xs text-gray-500">
                            {geofence.center_latitude.toFixed(4)}, {geofence.center_longitude.toFixed(4)}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Alerts Tab */}
              {activeTab === 'alerts' && (
                <div className="space-y-4">
                  <h3 className="font-semibold text-gray-900 dark:text-white">
                    Geofence Alerts
                    {unacknowledgedCount > 0 && (
                      <span className="ml-2 text-sm font-normal text-gray-500">
                        ({unacknowledgedCount} pending)
                      </span>
                    )}
                  </h3>

                  {alerts.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">No alerts</div>
                  ) : (
                    <div className="space-y-2">
                      {alerts.map((alert) => (
                        <div
                          key={alert.alert_id}
                          className={cn(
                            'p-3 rounded-lg border',
                            alert.acknowledged
                              ? 'bg-gray-50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600'
                              : 'bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-700'
                          )}
                        >
                          <div className="flex justify-between items-start">
                            <div>
                              <h4 className="font-medium text-gray-900 dark:text-white">
                                {alert.event_type.toUpperCase()} - {alert.geofence_name}
                              </h4>
                              <p className="text-xs text-gray-500 dark:text-gray-400">
                                Device: {alert.device_id}
                              </p>
                            </div>
                            {!alert.acknowledged && (
                              <button
                                onClick={() => acknowledgeAlert(alert.alert_id)}
                                disabled={isAcknowledging}
                                className="px-2 py-1 text-xs bg-blue-500 text-white rounded hover:bg-blue-600"
                              >
                                Acknowledge
                              </button>
                            )}
                          </div>
                          <div className="mt-2 text-xs text-gray-500">
                            {new Date(alert.timestamp).toLocaleString()}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Analysis Tab */}
              {activeTab === 'analysis' && (
                <div className="space-y-4">
                  <h3 className="font-semibold text-gray-900 dark:text-white">Movement Analysis</h3>

                  {!selectedDevice ? (
                    <div className="text-center py-8 text-gray-500">
                      Select a device to view analysis
                    </div>
                  ) : patterns ? (
                    <div className="space-y-4">
                      <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                          {selectedDevice.device_name}
                        </h4>
                        <p className="text-xs text-gray-500">
                          Analysis Period: {patterns.analysis_period}
                        </p>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20">
                          <div className="text-lg font-bold text-blue-600">
                            {patterns.average_daily_distance_km.toFixed(1)} km
                          </div>
                          <div className="text-xs text-gray-500">Avg Daily Distance</div>
                        </div>
                        <div className="p-3 rounded-lg bg-green-50 dark:bg-green-900/20">
                          <div className="text-lg font-bold text-green-600">
                            {(patterns.confidence_score * 100).toFixed(0)}%
                          </div>
                          <div className="text-xs text-gray-500">Confidence Score</div>
                        </div>
                      </div>

                      {patterns.home_location && (
                        <div className="p-3 rounded-lg border border-green-200 dark:border-green-800">
                          <div className="flex items-center gap-2">
                            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                            <span className="text-sm font-medium">Home Location</span>
                          </div>
                          <p className="text-xs text-gray-500 mt-1">
                            Confidence: {(patterns.home_location.confidence * 100).toFixed(0)}%
                          </p>
                        </div>
                      )}

                      {patterns.work_location && (
                        <div className="p-3 rounded-lg border border-purple-200 dark:border-purple-800">
                          <div className="flex items-center gap-2">
                            <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
                            <span className="text-sm font-medium">Work Location</span>
                          </div>
                          <p className="text-xs text-gray-500 mt-1">
                            Confidence: {(patterns.work_location.confidence * 100).toFixed(0)}%
                          </p>
                        </div>
                      )}

                      <div>
                        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Frequent Locations ({patterns.frequent_locations.length})
                        </h4>
                        <div className="space-y-1">
                          {patterns.frequent_locations.slice(0, 5).map((loc, idx) => (
                            <div
                              key={idx}
                              className="flex justify-between items-center text-xs p-2 rounded bg-gray-50 dark:bg-gray-700/50"
                            >
                              <span>Location #{idx + 1}</span>
                              <span className="text-gray-500">{loc.visit_count} visits</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-gray-500">Loading analysis...</div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default GeolocationPage;
