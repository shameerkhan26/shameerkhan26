import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../contexts/AuthContext';

interface Complaint {
  _id: string;
  subject: string;
  description: string;
  status: string;
  createdAt: string;
}

export default function ComplaintList() {
  const [complaints, setComplaints] = useState<Complaint[]>([]);
  const { user } = useAuth();

  useEffect(() => {
    const fetchComplaints = async () => {
      try {
        const response = await axios.get('http://localhost:5001/api/complaints', {
            headers: { Authorization: `Bearer ${user?.accessToken}` }
          });
          
        setComplaints(response.data);
      } catch (error) {
        console.error('Error fetching complaints:', error);
      }
    };

    if (user) {
      fetchComplaints();
    }
  }, [user]);

  return (
    <div className="mt-8">
      <h2 className="text-xl font-semibold mb-4">Your Complaints</h2>
      {complaints.length === 0 ? (
        <p>No complaints submitted yet.</p>
      ) : (
        <ul className="space-y-4">
          {complaints.map((complaint) => (
            <li key={complaint._id} className="bg-gray-100 p-4 rounded-md">
              <h3 className="font-semibold">{complaint.subject}</h3>
              <p className="text-sm text-gray-600">{complaint.description}</p>
              <div className="mt-2 text-xs text-gray-500">
                <span>{new Date(complaint.createdAt).toLocaleString()}</span>
                <span className="ml-2 px-2 py-1 bg-yellow-200 rounded-full">{complaint.status}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}