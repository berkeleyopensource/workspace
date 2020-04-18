import React from 'react';
import './SignInUp.css';

function App() {
  return (
    <div className="SignInUp">
      <nav>
        <h2>workspace</h2>
      </nav>
      <form>
        <h2>Sign in.</h2>
        <div className="input-group">
          <div className="input-title">Email Address</div>
          <input type="email"></input>
        </div>
        <div className="input-group">
          <div className="input-title">Password</div>
          <input type="password"></input>
        </div>
        <div className="input-group">
          <button className="button-primary" type="submit"><div>Continue</div></button>
        </div>
        <div className="input-group">
          <div><a href="/reset">Forgot your password?</a></div>
          <div>Need an account? <a href="/signup">Register.</a></div>
        </div>
      </form>
    </div>
  );
}

export default App;