/**
 * TrackingMap Component - Interactive Map with Tracking
 * Apollo Platform - Geolocation Frontend
 *
 * Provides interactive mapping capabilities with real-time tracking,
 * geofence visualization, and target location display.
 */

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Circle, Polyline, useMap, useMapEvents } from 'react-leaflet';
import L from 'leaflet';
import { cn } from '../../utils/cn';
import 'leaflet/dist/leaflet.css';

// Fix for default markers in React-Leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
});

// Custom marker icons
const createCustomIcon = (color: string, size: number = 25) => {
  return L.divIcon({
    className: 'custom-marker',
    html: `
      <div style="
        background-color: ${color};
        width: ${size}px;
        height: ${size}px;
        border-radius: 50% 50% 50% 0;
        transform: rotate(-45deg);
        border: 2px solid white;
        box-shadow: 0 2px 5px rgba(0,0,0,0.3);
      "></div>
    `,
    iconSize: [size, size],
    iconAnchor: [size / 2, size],
  });
};

const targetIcon = createCustomIcon('#ef4444', 30); // Red
const deviceIcon = createCustomIcon('#3b82f6', 25); // Blue
const alertIcon = createCustomIcon('#f59e0b', 28); // Yellow
const homeIcon = createCustomIcon('#22c55e', 25); // Green
const workIcon = createCustomIcon('#8b5cf6', 25); // Purple

// Types
export interface TrackedDevice {
  device_id: string;
  device_name: string;
  latitude: number;
  longitude: number;
  speed?: number;
  heading?: number;
  battery_level?: number;
  timestamp?: string;
  status?: 'active' | 'inactive' | 'offline';
}

export interface GeofenceZone {
  geofence_id: string;
  name: string;
  center_latitude: number;
  center_longitude: number;
  radius_meters: number;
  priority?: 'low' | 'medium' | 'high' | 'critical';
  active?: boolean;
}

export interface LocationPoint {
  latitude: number;
  longitude: number;
  timestamp?: string;
  label?: string;
  type?: 'home' | 'work' | 'alert' | 'point_of_interest' | 'custom';
}

export interface TrackingPath {
  device_id: string;
  points: { lat: number; lng: number }[];
  color?: string;
}

interface TrackingMapProps {
  /** Center position */
  center?: [number, number];
  /** Initial zoom level */
  zoom?: number;
  /** Tracked devices to display */
  devices?: TrackedDevice[];
  /** Geofence zones */
  geofences?: GeofenceZone[];
  /** Location points to display */
  points?: LocationPoint[];
  /** Movement tracks */
  tracks?: TrackingPath[];
  /** Show tracking trails for devices */
  showTrails?: boolean;
  /** Callback when map is clicked */
  onMapClick?: (lat: number, lng: number) => void;
  /** Callback when a device is clicked */
  onDeviceClick?: (device: TrackedDevice) => void;
  /** Callback when a geofence is clicked */
  onGeofenceClick?: (geofence: GeofenceZone) => void;
  /** Enable drawing mode for geofences */
  drawingMode?: boolean;
  /** Callback when geofence is drawn */
  onGeofenceDrawn?: (center: [number, number], radius: number) => void;
  /** Custom class name */
  className?: string;
  /** Height of the map */
  height?: string;
  /** Selected device to focus on */
  selectedDeviceId?: string;
  /** Show full screen button */
  showFullscreen?: boolean;
}

// Map event handler component
const MapEventHandler: React.FC<{
  onMapClick?: (lat: number, lng: number) => void;
  drawingMode?: boolean;
  onGeofenceDrawn?: (center: [number, number], radius: number) => void;
}> = ({ onMapClick, drawingMode, onGeofenceDrawn }) => {
  const [drawingCenter, setDrawingCenter] = useState<[number, number] | null>(null);

  useMapEvents({
    click: (e) => {
      if (drawingMode && onGeofenceDrawn) {
        if (!drawingCenter) {
          setDrawingCenter([e.latlng.lat, e.latlng.lng]);
        } else {
          const distance = e.latlng.distanceTo(L.latLng(drawingCenter[0], drawingCenter[1]));
          onGeofenceDrawn(drawingCenter, distance);
          setDrawingCenter(null);
        }
      } else {
        onMapClick?.(e.latlng.lat, e.latlng.lng);
      }
    },
  });

  return drawingCenter ? (
    <Circle
      center={drawingCenter}
      radius={100}
      pathOptions={{ color: '#3b82f6', fillOpacity: 0.2, dashArray: '5, 5' }}
    />
  ) : null;
};

// Auto-fit bounds component
const FitBounds: React.FC<{
  devices?: TrackedDevice[];
  points?: LocationPoint[];
  geofences?: GeofenceZone[];
}> = ({ devices = [], points = [], geofences = [] }) => {
  const map = useMap();

  useEffect(() => {
    const allPoints: [number, number][] = [];

    devices.forEach((d) => allPoints.push([d.latitude, d.longitude]));
    points.forEach((p) => allPoints.push([p.latitude, p.longitude]));
    geofences.forEach((g) => allPoints.push([g.center_latitude, g.center_longitude]));

    if (allPoints.length > 0) {
      const bounds = L.latLngBounds(allPoints);
      map.fitBounds(bounds, { padding: [50, 50] });
    }
  }, [devices, points, geofences, map]);

  return null;
};

// Focus on device component
const FocusOnDevice: React.FC<{
  device?: TrackedDevice;
}> = ({ device }) => {
  const map = useMap();

  useEffect(() => {
    if (device) {
      map.flyTo([device.latitude, device.longitude], 16, { duration: 1 });
    }
  }, [device, map]);

  return null;
};

export const TrackingMap: React.FC<TrackingMapProps> = ({
  center = [40.7128, -74.006],
  zoom = 12,
  devices = [],
  geofences = [],
  points = [],
  tracks = [],
  showTrails = true,
  onMapClick,
  onDeviceClick,
  onGeofenceClick,
  drawingMode = false,
  onGeofenceDrawn,
  className,
  height = '500px',
  selectedDeviceId,
  showFullscreen = true,
}) => {
  const [isFullscreen, setIsFullscreen] = useState(false);
  const mapContainerRef = useRef<HTMLDivElement>(null);

  const selectedDevice = devices.find((d) => d.device_id === selectedDeviceId);

  // Get icon based on point type
  const getPointIcon = (type?: string) => {
    switch (type) {
      case 'home':
        return homeIcon;
      case 'work':
        return workIcon;
      case 'alert':
        return alertIcon;
      default:
        return targetIcon;
    }
  };

  // Get geofence color based on priority
  const getGeofenceColor = (priority?: string) => {
    switch (priority) {
      case 'critical':
        return '#ef4444';
      case 'high':
        return '#f97316';
      case 'medium':
        return '#eab308';
      case 'low':
        return '#22c55e';
      default:
        return '#3b82f6';
    }
  };

  // Toggle fullscreen
  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement && mapContainerRef.current) {
      mapContainerRef.current.requestFullscreen();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  }, []);

  return (
    <div
      ref={mapContainerRef}
      className={cn('relative rounded-lg overflow-hidden shadow-lg', className)}
      style={{ height }}
    >
      <MapContainer
        center={center}
        zoom={zoom}
        style={{ height: '100%', width: '100%' }}
        className="z-0"
      >
        {/* Base tile layer */}
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {/* Dark mode tile layer alternative */}
        {/* <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        /> */}

        {/* Event handlers */}
        <MapEventHandler
          onMapClick={onMapClick}
          drawingMode={drawingMode}
          onGeofenceDrawn={onGeofenceDrawn}
        />

        {/* Auto-fit bounds (only if no selected device) */}
        {!selectedDeviceId && (devices.length > 0 || points.length > 0 || geofences.length > 0) && (
          <FitBounds devices={devices} points={points} geofences={geofences} />
        )}

        {/* Focus on selected device */}
        {selectedDevice && <FocusOnDevice device={selectedDevice} />}

        {/* Geofence zones */}
        {geofences.map((geofence) => (
          <Circle
            key={geofence.geofence_id}
            center={[geofence.center_latitude, geofence.center_longitude]}
            radius={geofence.radius_meters}
            pathOptions={{
              color: getGeofenceColor(geofence.priority),
              fillOpacity: geofence.active !== false ? 0.2 : 0.1,
              weight: 2,
              dashArray: geofence.active === false ? '5, 5' : undefined,
            }}
            eventHandlers={{
              click: () => onGeofenceClick?.(geofence),
            }}
          >
            <Popup>
              <div className="p-2">
                <h3 className="font-bold text-sm">{geofence.name}</h3>
                <p className="text-xs text-gray-600">
                  Radius: {geofence.radius_meters}m
                </p>
                <p className="text-xs text-gray-600">
                  Priority: {geofence.priority || 'medium'}
                </p>
                <p className="text-xs text-gray-600">
                  Status: {geofence.active !== false ? 'Active' : 'Inactive'}
                </p>
              </div>
            </Popup>
          </Circle>
        ))}

        {/* Movement tracks */}
        {tracks.map((track) => (
          <Polyline
            key={track.device_id}
            positions={track.points}
            pathOptions={{
              color: track.color || '#3b82f6',
              weight: 3,
              opacity: 0.7,
            }}
          />
        ))}

        {/* Tracked devices */}
        {devices.map((device) => (
          <Marker
            key={device.device_id}
            position={[device.latitude, device.longitude]}
            icon={deviceIcon}
            eventHandlers={{
              click: () => onDeviceClick?.(device),
            }}
          >
            <Popup>
              <div className="p-2 min-w-[200px]">
                <h3 className="font-bold text-sm">{device.device_name}</h3>
                <div className="mt-2 space-y-1 text-xs text-gray-600">
                  <p>
                    <span className="font-medium">Status:</span>{' '}
                    <span
                      className={cn(
                        'px-1.5 py-0.5 rounded-full',
                        device.status === 'active' && 'bg-green-100 text-green-800',
                        device.status === 'inactive' && 'bg-gray-100 text-gray-800',
                        device.status === 'offline' && 'bg-red-100 text-red-800'
                      )}
                    >
                      {device.status || 'active'}
                    </span>
                  </p>
                  {device.speed !== undefined && (
                    <p>
                      <span className="font-medium">Speed:</span> {device.speed.toFixed(1)} km/h
                    </p>
                  )}
                  {device.heading !== undefined && (
                    <p>
                      <span className="font-medium">Heading:</span> {device.heading.toFixed(0)}
                    </p>
                  )}
                  {device.battery_level !== undefined && (
                    <p>
                      <span className="font-medium">Battery:</span>{' '}
                      <span
                        className={cn(
                          device.battery_level > 50 && 'text-green-600',
                          device.battery_level <= 50 && device.battery_level > 20 && 'text-yellow-600',
                          device.battery_level <= 20 && 'text-red-600'
                        )}
                      >
                        {device.battery_level}%
                      </span>
                    </p>
                  )}
                  {device.timestamp && (
                    <p>
                      <span className="font-medium">Updated:</span>{' '}
                      {new Date(device.timestamp).toLocaleTimeString()}
                    </p>
                  )}
                </div>
                <p className="mt-2 text-xs text-gray-500">
                  {device.latitude.toFixed(6)}, {device.longitude.toFixed(6)}
                </p>
              </div>
            </Popup>
          </Marker>
        ))}

        {/* Location points */}
        {points.map((point, index) => (
          <Marker
            key={`point-${index}`}
            position={[point.latitude, point.longitude]}
            icon={getPointIcon(point.type)}
          >
            <Popup>
              <div className="p-2">
                <h3 className="font-bold text-sm">{point.label || 'Location'}</h3>
                {point.type && (
                  <p className="text-xs text-gray-600 capitalize">Type: {point.type}</p>
                )}
                {point.timestamp && (
                  <p className="text-xs text-gray-600">
                    {new Date(point.timestamp).toLocaleString()}
                  </p>
                )}
                <p className="mt-1 text-xs text-gray-500">
                  {point.latitude.toFixed(6)}, {point.longitude.toFixed(6)}
                </p>
              </div>
            </Popup>
          </Marker>
        ))}
      </MapContainer>

      {/* Map Controls */}
      <div className="absolute top-4 right-4 z-[1000] flex flex-col gap-2">
        {showFullscreen && (
          <button
            onClick={toggleFullscreen}
            className="p-2 bg-white dark:bg-gray-800 rounded-lg shadow-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            {isFullscreen ? (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
              </svg>
            )}
          </button>
        )}

        {drawingMode && (
          <div className="px-3 py-2 bg-blue-500 text-white rounded-lg shadow-lg text-sm">
            Click to set geofence center, then click again to set radius
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-[1000] bg-white dark:bg-gray-800 rounded-lg shadow-lg p-3">
        <h4 className="text-xs font-semibold mb-2 text-gray-700 dark:text-gray-300">Legend</h4>
        <div className="space-y-1 text-xs">
          {devices.length > 0 && (
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
              <span className="text-gray-600 dark:text-gray-400">Tracked Device</span>
            </div>
          )}
          {geofences.length > 0 && (
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 border-2 border-blue-500 rounded-full"></div>
              <span className="text-gray-600 dark:text-gray-400">Geofence Zone</span>
            </div>
          )}
          {points.some(p => p.type === 'home') && (
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-green-500 rounded-full"></div>
              <span className="text-gray-600 dark:text-gray-400">Home Location</span>
            </div>
          )}
          {points.some(p => p.type === 'work') && (
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
              <span className="text-gray-600 dark:text-gray-400">Work Location</span>
            </div>
          )}
          {points.some(p => p.type === 'alert') && (
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
              <span className="text-gray-600 dark:text-gray-400">Alert Location</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TrackingMap;
