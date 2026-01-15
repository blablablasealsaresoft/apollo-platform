import React from 'react';

const AdminPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Administration</h1>
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">User Management</h2>
          <p className="text-gray-500">Manage user accounts and permissions</p>
        </div>
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">System Configuration</h2>
          <p className="text-gray-500">Configure system settings</p>
        </div>
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">API Keys</h2>
          <p className="text-gray-500">Manage API keys and integrations</p>
        </div>
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">Audit Logs</h2>
          <p className="text-gray-500">View system audit logs</p>
        </div>
      </div>
    </div>
  );
};

export default AdminPage;
