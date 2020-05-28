import React from 'react';
import Navbar from "./components/Navbar";
import { Link } from 'react-router-dom';

class NotFound extends React.Component<any, any> {
  constructor(props: any) {
    super(props);
  }
  render() {
    return (
      <div>
        <Navbar/>
        <div>
          <h1>Workspace Not Found</h1>
          <p>Oops, it looks like the workspace you're trying to reach is no longer available.
            Click <Link to="/">here</Link> to return home.
          </p>
        </div>
      </div>
    )
  }
}

export default NotFound;