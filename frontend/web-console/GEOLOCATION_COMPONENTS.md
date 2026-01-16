# Geolocation Components - Frontend Integration

## Overview

Geolocation UI components for Apollo's web console, enabling interactive location search and mapping for criminal investigations.

---

## React-Geosuggest Integration

**Source**: [react-geosuggest](https://github.com/blablablasealsaresoft/react-geosuggest)  
**Purpose**: Google Maps Places API autosuggest for location intelligence  
**Status**: ✅ Integrated  
**Location**: `src/components/intelligence/` & `src/components/common/UI/`

### What is React-Geosuggest?

A React autosuggest component that provides:
- Google Maps Places API integration
- Location autocomplete
- Geocoding capabilities
- Custom fixture support
- BEM-styled CSS

### Use Cases in Apollo

#### 1. Predator Investigation - Location Tracking

**Location**: `src/components/intelligence/GEOINTViewer.tsx`

```typescript
import Geosuggest from 'react-geosuggest';
import { useGeolocation } from '@/hooks/useGeolocation';

// Track suspect locations
const PredatorLocationTracker = () => {
  const { addLocation, getSuspectHistory } = useGeolocation();

  const onLocationSelect = (suggest) => {
    addLocation({
      suspect: currentSuspect,
      location: suggest.location,
      label: suggest.label,
      timestamp: new Date(),
      source: 'manual-entry'
    });
  };

  return (
    <div className="predator-location-tracker">
      <h3>Add Suspect Location</h3>
      <Geosuggest
        placeholder="Enter location..."
        onSuggestSelect={onLocationSelect}
        types={['geocode']}
        country="us"
      />
      <SuspectLocationMap locations={getSuspectHistory()} />
    </div>
  );
};
```

#### 2. Cryptocurrency Crime - Exchange Location Mapping

**Location**: `src/components/investigation/TargetProfile.tsx`

```typescript
// Map cryptocurrency exchange physical locations
const CryptoExchangeLocations = ({ exchangeName }) => {
  const [locations, setLocations] = useState([]);

  const addExchangeLocation = (suggest) => {
    setLocations([...locations, {
      exchange: exchangeName,
      address: suggest.label,
      coordinates: suggest.location,
      verified: false
    }]);
  };

  return (
    <div className="crypto-exchange-locations">
      <h3>Physical Locations for {exchangeName}</h3>
      <Geosuggest
        placeholder="Search exchange offices, ATMs, meetup locations..."
        onSuggestSelect={addExchangeLocation}
        types={['establishment', 'geocode']}
      />
      <ExchangeLocationMap locations={locations} />
    </div>
  );
};
```

#### 3. Investigation Evidence - Crime Scene Mapping

**Location**: `src/components/investigation/EvidenceViewer.tsx`

```typescript
// Map evidence locations
const EvidenceLocationMapper = ({ caseId }) => {
  const onEvidenceLocationSelect = (suggest) => {
    apollo.evidence.addLocation({
      caseId,
      type: 'evidence-location',
      location: suggest.location,
      address: suggest.label,
      timestamp: new Date(),
      geocoded: true
    });
  };

  return (
    <Geosuggest
      placeholder="Add evidence location..."
      onSuggestSelect={onEvidenceLocationSelect}
      autoComplete="off"
    />
  );
};
```

#### 4. Surveillance Network - Camera Location Search

**Location**: `src/components/intelligence/GEOINTViewer.tsx`

```typescript
// Find surveillance cameras near location
const SurveillanceCameraFinder = () => {
  const findNearbyCameras = async (suggest) => {
    const cameras = await apollo.geoint.findCameras({
      location: suggest.location,
      radius: 5000, // 5km
      types: ['traffic', 'security', 'public']
    });

    displayCamerasOnMap(cameras);
  };

  return (
    <div className="surveillance-finder">
      <h3>Find Surveillance Cameras</h3>
      <Geosuggest
        placeholder="Enter location to find nearby cameras..."
        onSuggestSelect={findNearbyCameras}
        radius="5000"
      />
      <CameraMap />
    </div>
  );
};
```

#### 5. Geo-Fencing - Alert Zones

**Location**: `src/components/operations/GeoFencing.tsx`

```typescript
// Set up geofence alerts for suspects
const GeoFenceAlertSetup = ({ suspectId }) => {
  const createGeoFence = (suggest) => {
    apollo.alerts.createGeoFence({
      suspectId,
      center: suggest.location,
      radius: 1000, // 1km
      alertOn: ['entry', 'exit'],
      priority: 'high',
      notifyChannels: ['email', 'slack', 'mobile']
    });
  };

  return (
    <div className="geofence-setup">
      <h3>Create Geo-Fence Alert</h3>
      <Geosuggest
        placeholder="Center point for geo-fence..."
        onSuggestSelect={createGeoFence}
      />
      <label>
        Radius: <input type="number" /> meters
      </label>
    </div>
  );
};
```

### Advanced Features

#### Custom Fixtures for Frequent Locations

```typescript
// Predefined locations for quick access
const apolloFixtures = [
  {
    label: 'FBI Headquarters, Washington DC',
    location: { lat: 38.8977, lng: -77.0365 }
  },
  {
    label: 'Cryptocurrency Exchange District, Hong Kong',
    location: { lat: 22.2783, lng: 114.1747 }
  },
  {
    label: 'Dark Web Server Farm, Iceland',
    location: { lat: 64.1466, lng: -21.9426 }
  }
];

<Geosuggest
  fixtures={apolloFixtures}
  maxFixtures={5}
  placeholder="Quick location access..."
/>
```

#### Integration with Apollo Intelligence

```typescript
// Auto-populate from intelligence data
const IntelligenceLocationSuggest = ({ targetId }) => {
  const { knownLocations } = useIntelligence(targetId);

  const fixtures = knownLocations.map(loc => ({
    label: loc.description,
    location: loc.coordinates,
    className: `location-confidence-${loc.confidence}`
  }));

  return (
    <Geosuggest
      fixtures={fixtures}
      placeholder="Select from known locations..."
      onSuggestSelect={handleLocationSelect}
    />
  );
};
```

---

## Installation

### Package Installation

```bash
cd frontend/web-console
npm install react-geosuggest --save
```

### Google Maps API Setup

```typescript
// src/services/maps/google-maps-config.ts
export const GOOGLE_MAPS_CONFIG = {
  apiKey: process.env.VITE_GOOGLE_MAPS_API_KEY,
  libraries: ['places', 'geometry'],
  region: 'us',
  language: 'en'
};

// Load Google Maps script
import { Loader } from '@googlemaps/js-api-loader';

const loader = new Loader(GOOGLE_MAPS_CONFIG);
await loader.load();
```

### Styling

```css
/* src/styles/geosuggest.css */
.geosuggest {
  position: relative;
}

.geosuggest__input {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid #ccc;
  border-radius: 4px;
}

.geosuggest__suggests {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  max-height: 25em;
  padding: 0;
  margin-top: -1px;
  background: #fff;
  border: 1px solid #ccc;
  border-top: 0;
  overflow-x: hidden;
  overflow-y: auto;
  list-style: none;
  z-index: 5;
}

.geosuggest__suggests--hidden {
  max-height: 0;
  overflow: hidden;
  border-width: 0;
}

.geosuggest__item {
  padding: 0.5rem;
  cursor: pointer;
}

.geosuggest__item--active {
  background: #267dc0;
  color: #fff;
}

.geosuggest__item:hover {
  background: #f5f5f5;
}
```

---

## Mission-Specific Components

### Crypto Investigation Component

**File**: `src/components/investigation/CryptoLocationIntel.tsx`

```typescript
import React, { useState } from 'react';
import Geosuggest from 'react-geosuggest';
import { useCryptoInvestigation } from '@/hooks/useCryptoInvestigation';

export const CryptoLocationIntel = ({ walletAddress }) => {
  const { addLocationIntel } = useCryptoInvestigation();

  const handleLocationSelect = async (suggest) => {
    // Correlate location with crypto activity
    const correlation = await apollo.crypto.correlateLocation({
      wallet: walletAddress,
      location: suggest.location,
      address: suggest.label
    });

    addLocationIntel({
      wallet: walletAddress,
      location: suggest.location,
      address: suggest.label,
      correlation: correlation,
      nearbyExchanges: correlation.exchanges,
      nearbyATMs: correlation.bitcoinATMs,
      riskScore: correlation.riskScore
    });
  };

  return (
    <div className="crypto-location-intel">
      <h4>Location Intelligence for Wallet</h4>
      <Geosuggest
        placeholder="Search for exchange, ATM, or meeting locations..."
        onSuggestSelect={handleLocationSelect}
        types={['establishment', 'geocode']}
      />
    </div>
  );
};
```

### Predator Tracking Component

**File**: `src/components/investigation/PredatorLocationTracker.tsx`

```typescript
import React from 'react';
import Geosuggest from 'react-geosuggest';
import { usePredatorInvestigation } from '@/hooks/usePredatorInvestigation';

export const PredatorLocationTracker = ({ suspectId }) => {
  const { addLocationSighting, predictNextLocation } = usePredatorInvestigation();

  const handleLocationAdd = async (suggest) => {
    await addLocationSighting({
      suspectId,
      location: suggest.location,
      address: suggest.label,
      timestamp: new Date(),
      confidence: 'confirmed'
    });

    // AI predicts next location
    const prediction = await predictNextLocation(suspectId);
    displayPrediction(prediction);
  };

  return (
    <div className="predator-location-tracker">
      <h4>Add Suspect Sighting</h4>
      <Geosuggest
        placeholder="Where was suspect seen?"
        onSuggestSelect={handleLocationAdd}
      />
      
      <div className="location-history">
        <h5>Location History</h5>
        <LocationTimeline suspectId={suspectId} />
      </div>
      
      <div className="predicted-locations">
        <h5>AI-Predicted Locations</h5>
        <PredictedLocationMap suspectId={suspectId} />
      </div>
    </div>
  );
};
```

---

## Integration with Apollo Intelligence

### Auto-Population from OSINT

```typescript
// Auto-populate from OSINT intelligence
const IntelligenceGeoSuggest = ({ targetId }) => {
  const intelligence = useIntelligence(targetId);

  // Build fixtures from gathered intelligence
  const fixtures = [
    ...intelligence.socialMedia.geotaggedPosts.map(post => ({
      label: `${post.platform}: ${post.location}`,
      location: post.coordinates,
      className: 'intel-source-social'
    })),
    ...intelligence.photos.geolocation.map(photo => ({
      label: `Photo: ${photo.filename} - ${photo.predictedLocation}`,
      location: photo.coordinates,
      className: `intel-confidence-${photo.confidence}`
    })),
    ...intelligence.travel.knownLocations.map(travel => ({
      label: `Travel: ${travel.destination}`,
      location: travel.coordinates,
      className: 'intel-source-travel'
    }))
  ];

  return (
    <Geosuggest
      fixtures={fixtures}
      placeholder="Select from intelligence or search new..."
      onSuggestSelect={handleIntelSelect}
    />
  );
};
```

### Integration with Surveillance Network

```typescript
// Find nearby surveillance cameras
const SurveillanceLocationSearch = () => {
  const findCameras = async (suggest) => {
    // Query Apollo GEOINT engine
    const cameras = await apollo.geoint.findNearby({
      location: suggest.location,
      radius: 2000, // 2km
      types: ['traffic', 'security', 'webcam'],
      includePrivate: false
    });

    return cameras;
  };

  return (
    <Geosuggest
      placeholder="Find surveillance near..."
      onSuggestSelect={async (suggest) => {
        const cameras = await findCameras(suggest);
        displayCameras(cameras);
      }}
    />
  );
};
```

---

## Package Configuration

### Installation

**File**: `frontend/web-console/package.json`

```json
{
  "dependencies": {
    "react-geosuggest": "^2.14.0",
    "@googlemaps/js-api-loader": "^1.16.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  }
}
```

### Environment Variables

**File**: `.env`

```env
# Google Maps API Key (with Places API enabled)
VITE_GOOGLE_MAPS_API_KEY=your_google_maps_api_key

# Geolocation settings
VITE_GEOLOCATION_DEFAULT_RADIUS=5000
VITE_GEOLOCATION_MAX_RESULTS=10
```

---

## Component Props Configuration

### Apollo-Specific Configuration

```typescript
// Standard Apollo configuration
const apolloGeosuggestConfig = {
  // API
  googleMaps: window.google?.maps,
  
  // Appearance
  placeholder: 'Search location for investigation...',
  autoComplete: 'off',
  
  // Behavior
  autoActivateFirstSuggest: true,
  highlightMatch: true,
  queryDelay: 250,
  
  // Filtering
  types: ['geocode', 'establishment'],
  country: 'us', // or multi-country array
  
  // Styling
  className: 'apollo-geosuggest',
  suggestsClassName: 'apollo-geosuggest-suggestions',
  suggestItemActiveClassName: 'apollo-active'
};
```

### Advanced Props for Investigations

```typescript
<Geosuggest
  // Basic
  placeholder="Search suspect location..."
  initialValue={lastKnownLocation}
  
  // Google Maps API
  location={new google.maps.LatLng(40.7128, -74.0060)} // NYC center
  radius="50000" // 50km search radius
  types={['geocode', 'establishment']}
  country={['us', 'ca', 'mx']}
  
  // Fixtures (frequent locations)
  fixtures={[
    { label: 'Suspect Home', location: { lat: 40.7589, lng: -73.9851 } },
    { label: 'Victim Last Seen', location: { lat: 40.7614, lng: -73.9776 } }
  ]}
  maxFixtures={10}
  
  // Callbacks
  onSuggestSelect={handleLocationSelect}
  onFocus={() => console.log('Location search focused')}
  onBlur={(value) => console.log('Location search blurred:', value)}
  onChange={(value) => console.log('Search changed:', value)}
  onSuggestNoResults={(input) => console.log('No results for:', input)}
  
  // Custom rendering
  renderSuggestItem={(suggest) => (
    <div className="custom-suggest-item">
      <span className="location-name">{suggest.description}</span>
      <span className="location-type">{suggest.types[0]}</span>
    </div>
  )}
  
  // Filtering
  skipSuggest={(suggest) => {
    // Skip certain types
    return suggest.types.includes('route');
  }}
  
  // Styling
  className="apollo-location-search"
  suggestsClassName="apollo-suggestions"
  suggestItemClassName="apollo-suggest-item"
  suggestItemActiveClassName="apollo-active-suggestion"
/>
```

---

## Integration with Apollo GEOINT Engine

### Link to Surveillance Network

```typescript
import Geosuggest from 'react-geosuggest';
import { useGeoint } from '@/hooks/useGeoint';

const GeoIntelligenceSearch = () => {
  const geoint = useGeoint();

  const onLocationSelect = async (suggest) => {
    // Multi-source intelligence gathering
    const intelligence = await Promise.all([
      // Surveillance cameras
      geoint.findCameras(suggest.location, 5000),
      
      // Transportation hubs
      geoint.findTransportation(suggest.location),
      
      // WiFi networks
      geoint.findWiFiNetworks(suggest.location),
      
      // Mobile cell towers
      geoint.findCellTowers(suggest.location),
      
      // Points of interest
      geoint.findPOIs(suggest.location)
    ]);

    // Display comprehensive GEOINT
    displayGeoIntelligence(intelligence);
  };

  return (
    <Geosuggest
      placeholder="Enter location for GEOINT analysis..."
      onSuggestSelect={onLocationSelect}
    />
  );
};
```

### Photo Geolocation Correlation

```typescript
// Correlate AI photo geolocation with manual search
const PhotoLocationCorrelation = ({ photoId }) => {
  const aiPrediction = usePhotoGeolocation(photoId);

  const fixtures = aiPrediction.topLocations.map((loc, idx) => ({
    label: `AI Prediction #${idx + 1}: ${loc.name} (${loc.confidence}% confidence)`,
    location: loc.coordinates,
    className: `ai-prediction-${loc.confidence > 80 ? 'high' : 'medium'}`
  }));

  return (
    <div className="photo-location-correlation">
      <h4>Photo Geolocation</h4>
      <div className="ai-prediction">
        <strong>AI Prediction:</strong> {aiPrediction.topLocation}
      </div>
      
      <Geosuggest
        fixtures={fixtures}
        placeholder="Confirm or search alternative location..."
        onSuggestSelect={(suggest) => {
          confirmPhotoLocation(photoId, suggest.location);
        }}
      />
    </div>
  );
};
```

---

## Real-Time Investigation Features

### Live Location Tracking

```typescript
// Real-time suspect location updates
const LiveLocationTracker = ({ caseId }) => {
  const [locations, setLocations] = useState([]);

  const addRealTimeLocation = (suggest) => {
    const newLocation = {
      timestamp: new Date(),
      location: suggest.location,
      address: suggest.label,
      source: 'manual-sighting',
      reportedBy: currentOperator
    };

    setLocations([...locations, newLocation]);
    
    // Broadcast to team
    apollo.realtime.broadcast({
      channel: `case-${caseId}`,
      event: 'location-update',
      data: newLocation
    });

    // Check geofence violations
    apollo.alerts.checkGeofences(newLocation);
  };

  return (
    <div className="live-location-tracker">
      <Geosuggest
        placeholder="Report suspect sighting..."
        onSuggestSelect={addRealTimeLocation}
      />
      <LiveMap locations={locations} />
    </div>
  );
};
```

### Emergency Response

```typescript
// Emergency victim location entry
const EmergencyLocationEntry = ({ amberAlertId }) => {
  const handleEmergencyLocation = async (suggest) => {
    // Immediate alert
    await apollo.emergency.reportLocation({
      alertId: amberAlertId,
      location: suggest.location,
      address: suggest.label,
      priority: 'CRITICAL',
      timestamp: new Date()
    });

    // Find nearest law enforcement
    const nearestLE = await apollo.geoint.findNearestLawEnforcement(
      suggest.location
    );

    // Deploy surveillance
    const cameras = await apollo.geoint.activateSurveillance(
      suggest.location,
      5000 // 5km radius
    );

    // Alert all units
    apollo.emergency.alertAllUnits({
      location: suggest.location,
      nearestUnits: nearestLE
    });
  };

  return (
    <div className="emergency-location-entry">
      <div className="emergency-banner">⚠️ EMERGENCY MODE</div>
      <Geosuggest
        placeholder="ENTER VICTIM LOCATION IMMEDIATELY"
        onSuggestSelect={handleEmergencyLocation}
        autoActivateFirstSuggest={true}
      />
    </div>
  );
};
```

---

## Accessibility & UX

### Keyboard Navigation

```typescript
// Full keyboard support
const AccessibleGeosuggest = () => {
  return (
    <Geosuggest
      placeholder="Search location..."
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          // Clear and close
          geoRef.current?.clear();
        }
      }}
      ignoreTab={false} // Tab selects suggestion
      autoActivateFirstSuggest={true} // Arrow keys work immediately
    />
  );
};
```

### Loading States

```typescript
const GeosuggestWithLoading = () => {
  const [isLoading, setIsLoading] = useState(false);

  return (
    <div className="geosuggest-wrapper">
      {isLoading && <LoadingSpinner />}
      <Geosuggest
        placeholder="Searching..."
        onFocus={() => setIsLoading(true)}
        onBlur={() => setIsLoading(false)}
      />
    </div>
  );
};
```

---

## Integration with Apollo Maps

### Multi-Source Map Display

```typescript
// Display on Apollo unified map
const ApolloMapIntegration = () => {
  const { addMapMarker, addMapLayer } = useApolloMap();

  const onLocationSelect = (suggest) => {
    // Add to Apollo map
    addMapMarker({
      position: suggest.location,
      title: suggest.label,
      type: 'investigation-location',
      metadata: {
        placeId: suggest.placeId,
        timestamp: new Date()
      }
    });

    // Add surveillance layer
    addMapLayer({
      type: 'surveillance-cameras',
      center: suggest.location,
      radius: 2000
    });
  };

  return (
    <Geosuggest
      placeholder="Add location to investigation map..."
      onSuggestSelect={onLocationSelect}
    />
  );
};
```

---

## Testing

### Component Tests

```typescript
// tests/components/GeoLocationSearch.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import Geosuggest from 'react-geosuggest';

describe('Geosuggest Integration', () => {
  it('should search and select location', async () => {
    const onSelect = jest.fn();
    
    render(
      <Geosuggest
        placeholder="Search..."
        onSuggestSelect={onSelect}
      />
    );

    const input = screen.getByPlaceholderText('Search...');
    fireEvent.change(input, { target: { value: 'New York' } });

    // Wait for suggestions
    await screen.findByText(/New York/);
    
    // Select first suggestion
    fireEvent.click(screen.getByText(/New York/));
    
    expect(onSelect).toHaveBeenCalled();
  });
});
```

---

## References

- **react-geosuggest**: https://github.com/blablablasealsaresoft/react-geosuggest
- **Google Maps Places API**: https://developers.google.com/maps/documentation/places/web-service
- **Apollo GEOINT Engine**: `../../intelligence/geoint-engine/`
- **Apollo Map Components**: `src/components/common/UI/Map.tsx`

---

**Integration Status**: ✅ Complete  
**Location**: `frontend/web-console/src/components/`  
**Use Cases**: Predator tracking, crypto investigation, surveillance, emergency response  
**Status**: Ready for implementation
