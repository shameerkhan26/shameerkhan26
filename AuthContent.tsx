import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import LoginForm from './LoginForm';
import SignupForm from './SignupForm';
import ComplaintForm from './ComplaintForm';
import ComplaintList from './ComplaintList';

export default function AuthContent() {
  const { user, logout } = useAuth();
  const [showLogin, setShowLogin] = useState(true);

  if (user) {
    return (
      <div className="mt-8">
        <h2 className="text-xl font-semibold mb-4">Welcome, {user.username}!</h2>
        <ComplaintForm />
        <ComplaintList />
        <button
          onClick={logout}
          className="mt-4 w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
        >
          Log out
        </button>
      </div>
    );
  }

  return (
    <div className="mt-8">
      <div className="flex justify-between mb-4">
        <button
          onClick={() => setShowLogin(true)}
          className={`px-4 py-2 rounded-md ${showLogin ? 'bg-indigo-600 text-white' : 'bg-gray-200 text-gray-700'}`}
        >
          Login
        </button>
        <button
          onClick={() => setShowLogin(false)}
          className={`px-4 py-2 rounded-md ${!showLogin ? 'bg-indigo-600 text-white' : 'bg-gray-200 text-gray-700'}`}
        >
          Sign up
        </button>
      </div>
      {showLogin ? <LoginForm /> : <SignupForm />}
    </div>
  );
}