import React from 'react';
import { FiPlus } from 'react-icons/fi';

const IntelligenceListPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Intelligence Reports</h1>
        <button className="btn-primary flex items-center gap-2">
          <FiPlus /> New Report
        </button>
      </div>
      <div className="card">
        <p className="text-center text-gray-500 py-12">Intelligence reports will be displayed here</p>
      </div>
    </div>
  );
};

export default IntelligenceListPage;
