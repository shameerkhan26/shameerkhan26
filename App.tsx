import React from 'react';
import { AuthProvider } from './contexts/AuthContext';
import AuthContent from './components/AuthContent';

export default function App() {
  return (
    <AuthProvider>
      <div className="min-h-screen bg-gray-100 py-6 flex flex-col justify-center sm:py-12">
        <div className="relative py-3 sm:max-w-xl sm:mx-auto">
          <div className="absolute inset-0 bg-gradient-to-r from-cyan-400 to-light-blue-500 shadow-lg transform -skew-y-6 sm:skew-y-0 sm:-rotate-6 sm:rounded-3xl"></div>
          <div className="relative px-4 py-10 bg-white shadow-lg sm:rounded-3xl sm:p-20">
            <div className="max-w-md mx-auto">
              <div>
                <h1 className="text-2xl font-semibold">Online Complaint Register</h1>
              </div>
              <AuthContent />
            </div>
          </div>
        </div>
      </div>
    </AuthProvider>
  );
}