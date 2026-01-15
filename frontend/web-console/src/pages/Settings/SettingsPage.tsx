import React from 'react';

const SettingsPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Settings</h1>
      <div className="card">
        <h2 className="text-xl font-semibold mb-4">User Settings</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Theme</label>
            <select className="input">
              <option>Light</option>
              <option>Dark</option>
              <option>Auto</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Email Notifications</label>
            <input type="checkbox" /> Enable email notifications
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;
