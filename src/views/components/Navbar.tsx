import React from 'react';
import { Link } from 'react-router-dom';
import './Navbar.css';
import layers from'../../assets/layers.svg';

class Navbar extends React.Component {
  render() {
    return (
      <nav className="navbar">
        <div className="navbar-logo">
          <Link to="/">
            <img src={layers}/>
            <h1>workspace</h1>
          </Link>
        </div>
        <div className="navbar-menu">
          {this.props.children}
        </div>
      </nav>
    )
  }
}

export default Navbar;