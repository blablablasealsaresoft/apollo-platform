/**
 * LocationSearch Component - React-Geosuggest Integration
 * Apollo Platform - Geolocation Frontend
 *
 * Provides location search and autocomplete functionality using
 * Google Maps Places API through react-geosuggest.
 */

import React, { useRef, useEffect, useState, useCallback } from 'react';
import { cn } from '../../utils/cn';

// Type definitions for react-geosuggest
interface GeosuggestSuggest {
  label: string;
  placeId?: string;
  location?: {
    lat: number;
    lng: number;
  };
  gmaps?: google.maps.places.PlaceResult;
  isFixture?: boolean;
}

interface Fixture {
  label: string;
  location?: {
    lat: number;
    lng: number;
  };
  className?: string;
}

interface LocationSearchProps {
  /** Placeholder text */
  placeholder?: string;
  /** Initial value */
  initialValue?: string;
  /** Country restriction (ISO 3166-1 Alpha-2) */
  country?: string | string[];
  /** Search types to include */
  types?: string[];
  /** Location to bias results towards */
  location?: { lat: number; lng: number };
  /** Search radius in meters */
  radius?: number;
  /** Pre-defined fixtures/suggestions */
  fixtures?: Fixture[];
  /** Maximum fixtures to show */
  maxFixtures?: number;
  /** Callback when a location is selected */
  onSelect?: (suggest: GeosuggestSuggest) => void;
  /** Callback when input value changes */
  onChange?: (value: string) => void;
  /** Callback when no results found */
  onNoResults?: (userInput: string) => void;
  /** Custom class name */
  className?: string;
  /** Disable the input */
  disabled?: boolean;
  /** Auto-activate first suggestion */
  autoActivateFirstSuggest?: boolean;
  /** Query delay in milliseconds */
  queryDelay?: number;
  /** Label for the input */
  label?: string;
  /** Required field */
  required?: boolean;
  /** Error message */
  error?: string;
  /** Helper text */
  helperText?: string;
}

export const LocationSearch: React.FC<LocationSearchProps> = ({
  placeholder = 'Search location...',
  initialValue = '',
  country,
  types = ['geocode'],
  location,
  radius,
  fixtures = [],
  maxFixtures = 5,
  onSelect,
  onChange,
  onNoResults,
  className,
  disabled = false,
  autoActivateFirstSuggest = true,
  queryDelay = 250,
  label,
  required = false,
  error,
  helperText,
}) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [inputValue, setInputValue] = useState(initialValue);
  const [suggestions, setSuggestions] = useState<GeosuggestSuggest[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [activeSuggestionIndex, setActiveSuggestionIndex] = useState(-1);
  const [autocompleteService, setAutocompleteService] = useState<google.maps.places.AutocompleteService | null>(null);
  const [placesService, setPlacesService] = useState<google.maps.places.PlacesService | null>(null);
  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);

  // Initialize Google Maps services
  useEffect(() => {
    if (typeof google !== 'undefined' && google.maps && google.maps.places) {
      setAutocompleteService(new google.maps.places.AutocompleteService());
      // PlacesService requires a DOM element or map
      const div = document.createElement('div');
      setPlacesService(new google.maps.places.PlacesService(div));
    }
  }, []);

  // Search for places
  const searchPlaces = useCallback(
    async (query: string) => {
      if (!query || !autocompleteService) {
        setSuggestions(fixtures.slice(0, maxFixtures).map((f) => ({ ...f, isFixture: true })));
        return;
      }

      setIsLoading(true);

      const request: google.maps.places.AutocompletionRequest = {
        input: query,
        types: types,
      };

      if (country) {
        request.componentRestrictions = {
          country: Array.isArray(country) ? country : [country],
        };
      }

      if (location) {
        request.location = new google.maps.LatLng(location.lat, location.lng);
        if (radius) {
          request.radius = radius;
        }
      }

      autocompleteService.getPlacePredictions(request, (predictions, status) => {
        setIsLoading(false);

        if (status === google.maps.places.PlacesServiceStatus.OK && predictions) {
          const placeSuggestions: GeosuggestSuggest[] = predictions.map((p) => ({
            label: p.description,
            placeId: p.place_id,
          }));

          // Add fixtures at the beginning
          const fixtureResults = fixtures
            .filter((f) => f.label.toLowerCase().includes(query.toLowerCase()))
            .slice(0, maxFixtures)
            .map((f) => ({ ...f, isFixture: true }));

          setSuggestions([...fixtureResults, ...placeSuggestions]);
        } else if (status === google.maps.places.PlacesServiceStatus.ZERO_RESULTS) {
          setSuggestions([]);
          onNoResults?.(query);
        }
      });
    },
    [autocompleteService, country, types, location, radius, fixtures, maxFixtures, onNoResults]
  );

  // Handle input change with debounce
  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const value = e.target.value;
      setInputValue(value);
      setShowSuggestions(true);
      onChange?.(value);

      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }

      debounceTimerRef.current = setTimeout(() => {
        searchPlaces(value);
      }, queryDelay);
    },
    [onChange, queryDelay, searchPlaces]
  );

  // Get place details and call onSelect
  const handleSuggestionSelect = useCallback(
    (suggest: GeosuggestSuggest) => {
      setInputValue(suggest.label);
      setShowSuggestions(false);
      setSuggestions([]);

      if (suggest.isFixture && suggest.location) {
        // Fixture with location already defined
        onSelect?.(suggest);
      } else if (suggest.placeId && placesService) {
        // Need to get place details
        placesService.getDetails(
          {
            placeId: suggest.placeId,
            fields: ['geometry', 'formatted_address', 'name'],
          },
          (place, status) => {
            if (status === google.maps.places.PlacesServiceStatus.OK && place?.geometry?.location) {
              const selectedSuggest: GeosuggestSuggest = {
                ...suggest,
                location: {
                  lat: place.geometry.location.lat(),
                  lng: place.geometry.location.lng(),
                },
                gmaps: place,
              };
              onSelect?.(selectedSuggest);
            }
          }
        );
      } else {
        onSelect?.(suggest);
      }
    },
    [onSelect, placesService]
  );

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!showSuggestions || suggestions.length === 0) return;

      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          setActiveSuggestionIndex((prev) => (prev < suggestions.length - 1 ? prev + 1 : 0));
          break;
        case 'ArrowUp':
          e.preventDefault();
          setActiveSuggestionIndex((prev) => (prev > 0 ? prev - 1 : suggestions.length - 1));
          break;
        case 'Enter':
          e.preventDefault();
          if (activeSuggestionIndex >= 0) {
            handleSuggestionSelect(suggestions[activeSuggestionIndex]);
          } else if (autoActivateFirstSuggest && suggestions.length > 0) {
            handleSuggestionSelect(suggestions[0]);
          }
          break;
        case 'Escape':
          setShowSuggestions(false);
          break;
      }
    },
    [showSuggestions, suggestions, activeSuggestionIndex, handleSuggestionSelect, autoActivateFirstSuggest]
  );

  // Clear input
  const handleClear = () => {
    setInputValue('');
    setSuggestions([]);
    setShowSuggestions(false);
    inputRef.current?.focus();
  };

  // Show suggestions on focus
  const handleFocus = () => {
    setShowSuggestions(true);
    if (!inputValue && fixtures.length > 0) {
      setSuggestions(fixtures.slice(0, maxFixtures).map((f) => ({ ...f, isFixture: true })));
    }
  };

  // Hide suggestions on blur (with delay to allow clicking)
  const handleBlur = () => {
    setTimeout(() => setShowSuggestions(false), 200);
  };

  return (
    <div className={cn('relative', className)}>
      {label && (
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          {label}
          {required && <span className="text-red-500 ml-1">*</span>}
        </label>
      )}

      <div className="relative">
        {/* Search Icon */}
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <svg
            className="h-5 w-5 text-gray-400"
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 20 20"
            fill="currentColor"
          >
            <path
              fillRule="evenodd"
              d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z"
              clipRule="evenodd"
            />
          </svg>
        </div>

        {/* Input */}
        <input
          ref={inputRef}
          type="text"
          value={inputValue}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          onFocus={handleFocus}
          onBlur={handleBlur}
          placeholder={placeholder}
          disabled={disabled}
          autoComplete="off"
          className={cn(
            'w-full pl-10 pr-10 py-2 border rounded-lg',
            'bg-white dark:bg-gray-800',
            'text-gray-900 dark:text-gray-100',
            'placeholder-gray-400 dark:placeholder-gray-500',
            'focus:ring-2 focus:ring-blue-500 focus:border-blue-500',
            'disabled:bg-gray-100 disabled:cursor-not-allowed',
            error ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
          )}
        />

        {/* Loading Spinner */}
        {isLoading && (
          <div className="absolute inset-y-0 right-8 flex items-center">
            <svg className="animate-spin h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
          </div>
        )}

        {/* Clear Button */}
        {inputValue && !disabled && (
          <button
            type="button"
            onClick={handleClear}
            className="absolute inset-y-0 right-0 pr-3 flex items-center"
          >
            <svg
              className="h-5 w-5 text-gray-400 hover:text-gray-600"
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                clipRule="evenodd"
              />
            </svg>
          </button>
        )}
      </div>

      {/* Suggestions Dropdown */}
      {showSuggestions && suggestions.length > 0 && (
        <ul
          className={cn(
            'absolute z-50 w-full mt-1 bg-white dark:bg-gray-800',
            'border border-gray-300 dark:border-gray-600 rounded-lg shadow-lg',
            'max-h-60 overflow-auto'
          )}
        >
          {suggestions.map((suggest, index) => (
            <li
              key={suggest.placeId || `fixture-${index}`}
              onClick={() => handleSuggestionSelect(suggest)}
              className={cn(
                'px-4 py-2 cursor-pointer',
                'hover:bg-blue-50 dark:hover:bg-blue-900/20',
                index === activeSuggestionIndex && 'bg-blue-100 dark:bg-blue-900/30',
                suggest.isFixture && 'bg-gray-50 dark:bg-gray-700/50'
              )}
            >
              <div className="flex items-center">
                {suggest.isFixture ? (
                  <svg className="h-4 w-4 mr-2 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                  </svg>
                ) : (
                  <svg className="h-4 w-4 mr-2 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M5.05 4.05a7 7 0 119.9 9.9L10 18.9l-4.95-4.95a7 7 0 010-9.9zM10 11a2 2 0 100-4 2 2 0 000 4z" clipRule="evenodd" />
                  </svg>
                )}
                <span className="text-sm text-gray-900 dark:text-gray-100">
                  {suggest.label}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}

      {/* No Results Message */}
      {showSuggestions && inputValue && suggestions.length === 0 && !isLoading && (
        <div className="absolute z-50 w-full mt-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg shadow-lg p-3 text-center text-gray-500 text-sm">
          No locations found for "{inputValue}"
        </div>
      )}

      {/* Error Message */}
      {error && (
        <p className="mt-1 text-sm text-red-500">{error}</p>
      )}

      {/* Helper Text */}
      {helperText && !error && (
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{helperText}</p>
      )}
    </div>
  );
};

export default LocationSearch;
