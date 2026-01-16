import React, { useState, useRef, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { facialService } from '@services/api';
import { FacialMatch } from '@types/index';
import { formatDate, formatRelativeTime } from '@utils/formatters';
import toast from 'react-hot-toast';
import {
  FiUpload,
  FiSearch,
  FiCamera,
  FiCheck,
  FiX,
  FiAlertCircle,
  FiUser,
  FiImage,
  FiTrash2,
  FiRefreshCw,
  FiEye,
  FiDownload,
  FiPercent,
  FiClock,
  FiMapPin,
} from 'react-icons/fi';

type TabType = 'search' | 'matches' | 'database' | 'compare';

const FacialRecognitionPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('search');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [searchThreshold, setSearchThreshold] = useState(70);
  const [maxResults, setMaxResults] = useState(10);
  const [searchResults, setSearchResults] = useState<FacialMatch[] | null>(null);
  const [compareFile1, setCompareFile1] = useState<File | null>(null);
  const [compareFile2, setCompareFile2] = useState<File | null>(null);
  const [comparePreview1, setComparePreview1] = useState<string | null>(null);
  const [comparePreview2, setComparePreview2] = useState<string | null>(null);
  const [compareResult, setCompareResult] = useState<{ match: boolean; confidence: number } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const compare1Ref = useRef<HTMLInputElement>(null);
  const compare2Ref = useRef<HTMLInputElement>(null);

  const { data: recentMatches, isLoading: matchesLoading } = useQuery({
    queryKey: ['facial-matches'],
    queryFn: async () => {
      const response = await facialService.getMatches();
      return response.data as FacialMatch[];
    },
  });

  const { data: faceDatabase, isLoading: databaseLoading } = useQuery({
    queryKey: ['facial-database'],
    queryFn: async () => {
      const response = await facialService.getFaceDatabase();
      return response.data || [];
    },
  });

  const searchMutation = useMutation({
    mutationFn: async () => {
      if (!selectedFile) throw new Error('No file selected');
      return facialService.searchByImage(selectedFile, {
        threshold: searchThreshold / 100,
        maxResults,
      });
    },
    onSuccess: (response) => {
      setSearchResults(response.data?.matches || []);
      if (response.data?.matches?.length === 0) {
        toast.success('Search complete - no matches found');
      } else {
        toast.success(`Found ${response.data?.matches?.length} potential matches`);
      }
    },
    onError: () => toast.error('Search failed. Please try again.'),
  });

  const verifyMutation = useMutation({
    mutationFn: async ({ matchId, verified, notes }: { matchId: string; verified: boolean; notes?: string }) => {
      return facialService.verifyMatch(matchId, verified, notes);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['facial-matches'] });
      toast.success('Match verification updated');
    },
    onError: () => toast.error('Failed to update verification'),
  });

  const compareMutation = useMutation({
    mutationFn: async () => {
      if (!compareFile1 || !compareFile2) throw new Error('Both images required');
      return facialService.compareFaces(compareFile1, compareFile2);
    },
    onSuccess: (response) => {
      setCompareResult(response.data || null);
    },
    onError: () => toast.error('Comparison failed'),
  });

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
      setSearchResults(null);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file && file.type.startsWith('image/')) {
      setSelectedFile(file);
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
      setSearchResults(null);
    }
  }, []);

  const handleCompareFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>, which: 1 | 2) => {
    const file = e.target.files?.[0];
    if (file) {
      const url = URL.createObjectURL(file);
      if (which === 1) {
        setCompareFile1(file);
        setComparePreview1(url);
      } else {
        setCompareFile2(file);
        setComparePreview2(url);
      }
      setCompareResult(null);
    }
  }, []);

  const clearSearch = () => {
    setSelectedFile(null);
    setPreviewUrl(null);
    setSearchResults(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const tabs = [
    { id: 'search', label: 'Face Search', icon: FiSearch },
    { id: 'matches', label: 'Recent Matches', icon: FiUser },
    { id: 'database', label: 'Face Database', icon: FiImage },
    { id: 'compare', label: 'Compare Faces', icon: FiPercent },
  ] as const;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Facial Recognition</h1>
          <p className="mt-1 text-sm text-gray-500">Search and identify targets using facial recognition technology</p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
              <FiUser className="h-6 w-6 text-primary-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Faces in Database</p>
              <p className="text-2xl font-bold">{faceDatabase?.length || 0}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-success-100 dark:bg-success-900/30 rounded-lg">
              <FiCheck className="h-6 w-6 text-success-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Verified Matches</p>
              <p className="text-2xl font-bold">{recentMatches?.filter(m => m.verified).length || 0}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-warning-100 dark:bg-warning-900/30 rounded-lg">
              <FiAlertCircle className="h-6 w-6 text-warning-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Pending Review</p>
              <p className="text-2xl font-bold">{recentMatches?.filter(m => !m.verified).length || 0}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
              <FiCamera className="h-6 w-6 text-purple-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Total Matches</p>
              <p className="text-2xl font-bold">{recentMatches?.length || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-200 dark:border-dark-700">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Search Tab */}
      {activeTab === 'search' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="card">
            <h2 className="text-lg font-semibold mb-4">Upload Image</h2>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              onChange={handleFileSelect}
              className="hidden"
            />
            {!previewUrl ? (
              <div
                onDrop={handleDrop}
                onDragOver={(e) => e.preventDefault()}
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-gray-300 dark:border-dark-600 rounded-lg p-12 text-center cursor-pointer hover:border-primary-500 transition-colors"
              >
                <FiUpload className="mx-auto h-12 w-12 text-gray-400" />
                <p className="mt-4 text-gray-600 dark:text-gray-400">
                  Drag and drop an image or click to upload
                </p>
                <p className="mt-2 text-sm text-gray-500">Supports JPG, PNG, WEBP (max 10MB)</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="relative">
                  <img src={previewUrl} alt="Preview" className="w-full h-64 object-contain rounded-lg bg-gray-100 dark:bg-dark-700" />
                  <button
                    onClick={clearSearch}
                    className="absolute top-2 right-2 p-2 bg-white dark:bg-dark-800 rounded-full shadow-lg hover:bg-gray-100"
                  >
                    <FiX className="h-4 w-4" />
                  </button>
                </div>
                <p className="text-sm text-gray-500">{selectedFile?.name}</p>
              </div>
            )}

            <div className="mt-6 space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">
                  Match Threshold: {searchThreshold}%
                </label>
                <input
                  type="range"
                  min={50}
                  max={99}
                  value={searchThreshold}
                  onChange={(e) => setSearchThreshold(parseInt(e.target.value))}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-gray-500">
                  <span>50% (More results)</span>
                  <span>99% (Higher accuracy)</span>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Max Results</label>
                <select
                  value={maxResults}
                  onChange={(e) => setMaxResults(parseInt(e.target.value))}
                  className="input w-full"
                >
                  <option value={5}>5 results</option>
                  <option value={10}>10 results</option>
                  <option value={25}>25 results</option>
                  <option value={50}>50 results</option>
                </select>
              </div>
              <button
                onClick={() => searchMutation.mutate()}
                disabled={!selectedFile || searchMutation.isPending}
                className="btn-primary w-full flex items-center justify-center gap-2"
              >
                {searchMutation.isPending ? (
                  <>
                    <div className="spinner h-4 w-4 border-2" />
                    Searching...
                  </>
                ) : (
                  <>
                    <FiSearch className="h-4 w-4" />
                    Search Database
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="card">
            <h2 className="text-lg font-semibold mb-4">Search Results</h2>
            {searchResults === null ? (
              <div className="text-center py-12 text-gray-500">
                <FiSearch className="mx-auto h-12 w-12 text-gray-400" />
                <p className="mt-4">Upload an image and click search to find matches</p>
              </div>
            ) : searchResults.length === 0 ? (
              <div className="text-center py-12">
                <FiX className="mx-auto h-12 w-12 text-gray-400" />
                <p className="mt-4 text-gray-500">No matches found above {searchThreshold}% confidence</p>
                <p className="text-sm text-gray-400 mt-2">Try lowering the threshold or using a clearer image</p>
              </div>
            ) : (
              <div className="space-y-4 max-h-[500px] overflow-y-auto">
                {searchResults.map((match) => (
                  <div key={match.id} className="p-4 border border-gray-200 dark:border-dark-700 rounded-lg hover:shadow-md transition-shadow">
                    <div className="flex gap-4">
                      <div className="w-20 h-20 rounded-lg bg-gray-200 dark:bg-dark-700 flex items-center justify-center overflow-hidden">
                        {match.matchedTarget?.photo ? (
                          <img src={match.matchedTarget.photo} alt="" className="w-full h-full object-cover" />
                        ) : (
                          <FiUser className="h-8 w-8 text-gray-400" />
                        )}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-start justify-between">
                          <div>
                            <h3 className="font-semibold">
                              {match.matchedTarget?.firstName} {match.matchedTarget?.lastName}
                            </h3>
                            <div className="flex items-center gap-2 mt-1">
                              <span className={`text-lg font-bold ${match.confidence >= 0.9 ? 'text-success-600' : match.confidence >= 0.7 ? 'text-warning-600' : 'text-gray-600'}`}>
                                {Math.round(match.confidence * 100)}%
                              </span>
                              <span className="text-sm text-gray-500">confidence</span>
                            </div>
                          </div>
                          <div className="flex items-center gap-1">
                            {match.verified ? (
                              <span className="badge badge-success flex items-center gap-1">
                                <FiCheck className="h-3 w-3" /> Verified
                              </span>
                            ) : (
                              <span className="badge badge-warning">Pending Review</span>
                            )}
                          </div>
                        </div>
                        {match.location && (
                          <div className="flex items-center gap-1 text-sm text-gray-500 mt-2">
                            <FiMapPin className="h-3 w-3" />
                            {match.location}
                          </div>
                        )}
                        {match.timestamp && (
                          <div className="flex items-center gap-1 text-sm text-gray-500 mt-1">
                            <FiClock className="h-3 w-3" />
                            {formatRelativeTime(match.timestamp)}
                          </div>
                        )}
                        <div className="mt-3 flex gap-2">
                          <button className="btn-secondary btn-sm flex items-center gap-1">
                            <FiEye className="h-3 w-3" /> View Profile
                          </button>
                          {!match.verified && (
                            <>
                              <button
                                onClick={() => verifyMutation.mutate({ matchId: match.id, verified: true })}
                                className="btn-secondary btn-sm text-success-600 flex items-center gap-1"
                              >
                                <FiCheck className="h-3 w-3" /> Verify
                              </button>
                              <button
                                onClick={() => verifyMutation.mutate({ matchId: match.id, verified: false, notes: 'Rejected by user' })}
                                className="btn-secondary btn-sm text-danger-600 flex items-center gap-1"
                              >
                                <FiX className="h-3 w-3" /> Reject
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recent Matches Tab */}
      {activeTab === 'matches' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Recent Facial Matches</h2>
            <button
              onClick={() => queryClient.invalidateQueries({ queryKey: ['facial-matches'] })}
              className="btn-secondary btn-sm flex items-center gap-1"
            >
              <FiRefreshCw className="h-4 w-4" /> Refresh
            </button>
          </div>
          {matchesLoading ? (
            <div className="flex justify-center py-12"><div className="spinner" /></div>
          ) : recentMatches && recentMatches.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-dark-700">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Match</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Confidence</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Source</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Location</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Time</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-500">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-dark-700">
                  {recentMatches.map((match) => (
                    <tr key={match.id} className="hover:bg-gray-50 dark:hover:bg-dark-700">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full bg-gray-200 dark:bg-dark-700 flex items-center justify-center">
                            {match.matchedTarget?.photo ? (
                              <img src={match.matchedTarget.photo} alt="" className="w-full h-full rounded-full object-cover" />
                            ) : (
                              <span className="text-sm font-semibold">
                                {match.matchedTarget?.firstName?.[0]}{match.matchedTarget?.lastName?.[0]}
                              </span>
                            )}
                          </div>
                          <span className="font-medium">
                            {match.matchedTarget?.firstName} {match.matchedTarget?.lastName}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-semibold ${match.confidence >= 0.9 ? 'text-success-600' : match.confidence >= 0.7 ? 'text-warning-600' : 'text-gray-600'}`}>
                          {Math.round(match.confidence * 100)}%
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500">{match.source}</td>
                      <td className="px-4 py-3 text-sm text-gray-500">{match.location || '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-500">{formatRelativeTime(match.timestamp)}</td>
                      <td className="px-4 py-3">
                        {match.verified ? (
                          <span className="badge badge-success">Verified</span>
                        ) : (
                          <span className="badge badge-warning">Pending</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1">
                          <button className="btn-secondary btn-sm"><FiEye className="h-4 w-4" /></button>
                          {!match.verified && (
                            <button
                              onClick={() => verifyMutation.mutate({ matchId: match.id, verified: true })}
                              className="btn-secondary btn-sm text-success-600"
                            >
                              <FiCheck className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12">
              <FiUser className="mx-auto h-12 w-12 text-gray-400" />
              <p className="mt-4 text-gray-500">No recent matches found</p>
            </div>
          )}
        </div>
      )}

      {/* Database Tab */}
      {activeTab === 'database' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Face Database</h2>
            <button className="btn-primary btn-sm flex items-center gap-1">
              <FiUpload className="h-4 w-4" /> Enroll New Face
            </button>
          </div>
          {databaseLoading ? (
            <div className="flex justify-center py-12"><div className="spinner" /></div>
          ) : faceDatabase && faceDatabase.length > 0 ? (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-4">
              {faceDatabase.map((face: any, i: number) => (
                <div key={i} className="group relative">
                  <div className="aspect-square rounded-lg bg-gray-200 dark:bg-dark-700 overflow-hidden">
                    {face.photo ? (
                      <img src={face.photo} alt="" className="w-full h-full object-cover" />
                    ) : (
                      <div className="w-full h-full flex items-center justify-center">
                        <FiUser className="h-12 w-12 text-gray-400" />
                      </div>
                    )}
                  </div>
                  <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity rounded-lg flex items-center justify-center gap-2">
                    <button className="p-2 bg-white rounded-full"><FiEye className="h-4 w-4" /></button>
                    <button className="p-2 bg-white rounded-full text-danger-600"><FiTrash2 className="h-4 w-4" /></button>
                  </div>
                  <p className="mt-2 text-sm font-medium truncate">{face.name || 'Unknown'}</p>
                  <p className="text-xs text-gray-500">{face.targetId ? 'Linked' : 'Unlinked'}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <FiImage className="mx-auto h-12 w-12 text-gray-400" />
              <p className="mt-4 text-gray-500">No faces enrolled in database</p>
              <button className="mt-4 btn-primary">Enroll First Face</button>
            </div>
          )}
        </div>
      )}

      {/* Compare Tab */}
      {activeTab === 'compare' && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Compare Two Faces</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <input
                ref={compare1Ref}
                type="file"
                accept="image/*"
                onChange={(e) => handleCompareFileSelect(e, 1)}
                className="hidden"
              />
              <div
                onClick={() => compare1Ref.current?.click()}
                className="aspect-square border-2 border-dashed border-gray-300 dark:border-dark-600 rounded-lg cursor-pointer hover:border-primary-500 transition-colors overflow-hidden"
              >
                {comparePreview1 ? (
                  <img src={comparePreview1} alt="Face 1" className="w-full h-full object-cover" />
                ) : (
                  <div className="w-full h-full flex flex-col items-center justify-center text-gray-400">
                    <FiUpload className="h-12 w-12" />
                    <p className="mt-2">Upload First Image</p>
                  </div>
                )}
              </div>
            </div>
            <div>
              <input
                ref={compare2Ref}
                type="file"
                accept="image/*"
                onChange={(e) => handleCompareFileSelect(e, 2)}
                className="hidden"
              />
              <div
                onClick={() => compare2Ref.current?.click()}
                className="aspect-square border-2 border-dashed border-gray-300 dark:border-dark-600 rounded-lg cursor-pointer hover:border-primary-500 transition-colors overflow-hidden"
              >
                {comparePreview2 ? (
                  <img src={comparePreview2} alt="Face 2" className="w-full h-full object-cover" />
                ) : (
                  <div className="w-full h-full flex flex-col items-center justify-center text-gray-400">
                    <FiUpload className="h-12 w-12" />
                    <p className="mt-2">Upload Second Image</p>
                  </div>
                )}
              </div>
            </div>
          </div>
          <div className="mt-6 flex flex-col items-center">
            <button
              onClick={() => compareMutation.mutate()}
              disabled={!compareFile1 || !compareFile2 || compareMutation.isPending}
              className="btn-primary flex items-center gap-2"
            >
              {compareMutation.isPending ? 'Comparing...' : 'Compare Faces'}
            </button>
            {compareResult && (
              <div className={`mt-6 p-6 rounded-lg text-center ${compareResult.match ? 'bg-success-50 dark:bg-success-900/20' : 'bg-danger-50 dark:bg-danger-900/20'}`}>
                <div className={`text-5xl font-bold ${compareResult.match ? 'text-success-600' : 'text-danger-600'}`}>
                  {Math.round(compareResult.confidence * 100)}%
                </div>
                <p className={`text-lg mt-2 ${compareResult.match ? 'text-success-700' : 'text-danger-700'}`}>
                  {compareResult.match ? 'MATCH FOUND' : 'NO MATCH'}
                </p>
                <p className="text-sm text-gray-500 mt-1">
                  {compareResult.match
                    ? 'These images appear to be the same person'
                    : 'These images appear to be different people'}
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default FacialRecognitionPage;
