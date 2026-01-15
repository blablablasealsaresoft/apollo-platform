import React from 'react';
import { FiUpload } from 'react-icons/fi';

const FacialRecognitionPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Facial Recognition</h1>
      <div className="card">
        <div className="text-center py-12">
          <FiUpload className="mx-auto h-12 w-12 text-gray-400" />
          <p className="mt-4 text-gray-600">Upload an image to search for facial matches</p>
          <button className="btn-primary mt-4">Upload Image</button>
        </div>
      </div>
    </div>
  );
};

export default FacialRecognitionPage;
