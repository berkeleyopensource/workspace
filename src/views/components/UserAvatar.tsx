import React from 'react';
import "./UserAvatar.css";

class UserAvatar extends React.Component {


  render() {
    return <div className="user-avatar" role="img">
      <svg viewBox="0 0 32 32">
        <foreignObject><img src="https://avatars2.githubusercontent.com/u/61579502?s=460&u=8fcfb6f825eded66734a9476b58b8f918aa3610e" alt="user-avatar"></img></foreignObject>
        <circle r="6" cx="26" cy="26"></circle>
      </svg>
    </div>
  }
}

export default UserAvatar;