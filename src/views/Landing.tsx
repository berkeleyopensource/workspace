import React from 'react';
import { Link } from 'react-router-dom';
import Navbar from "./components/Navbar";
import './Landing.css';

class Landing extends React.Component {
  render() {
    return (
      <div className="landing">
        <Navbar>
          <a href="#about">About</a>
          <span>|</span>
          <Link to="/signin">Log in</Link>
          <Link to="/signup">Sign up</Link>
        </Navbar>
        <div className="content">
          <section id="splash">
            <div className="splash-title">
              <h1>Effortless context switching</h1>
              <h2>Move between and share your workflows.</h2>
            </div>
          </section>
        </div>
      </div>
    )
  }
}

export default Landing;