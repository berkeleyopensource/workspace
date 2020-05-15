import React from 'react';
import './Workspace.css';

import UserAvatar from "./components/UserAvatar";

function App() {
  return (
    <div className="workspace">
      <div className="sidebar">
        hi
      </div>
      <div className="content">
        <div className="user-status">
          <UserAvatar/>
          <div className="user-custom">
            <div className="user-name">bob</div>
            <div>🐒text editin'</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
