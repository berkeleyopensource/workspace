import React from 'react';
import './Settings.css';

class Settings extends React.Component<any, any> {
  constructor(props: any) {
    super(props);
    this.state = {active: 0};
  }
  render() {
    const { active } = this.state;
    return (
      <div className="settings">
        <div className="sidebar">
          <nav>
            <div className="nav-title">User Settings</div>
            <div className={`nav-button ${this.state.active === 0 ? 'active' : ''}`} role="button" onClick={() => this.setState({active: 0})}>My Account</div>
            <div className={`nav-button ${this.state.active === 1 ? 'active' : ''}`} role="button" onClick={() => this.setState({active: 1})}>Preferences</div>
            <hr></hr>
            <div className="nav-title">App Settings</div>
            <div className={`nav-button ${this.state.active === 2 ? 'active' : ''}`} role="button" onClick={() => this.setState({active: 2})}>Appearance</div>
            <div className={`nav-button ${this.state.active === 3 ? 'active' : ''}`} role="button" onClick={() => this.setState({active: 3})}>App Activity</div>
            <hr></hr>
            <div className={`nav-button ${this.state.active === 4 ? 'active' : ''}`} role="button" onClick={() => this.setState({active: 4})}>Change Log</div>
            <div className="nav-button button-danger" role="button">Log Out</div>
          </nav>
        </div>
        <div className="content">
          {active === 0 && <section>
            <h2 className="section-title">My Account</h2>
          </section>}
          {active === 1 && <section>
            <h2 className="section-title">Preferences</h2>
          </section>}
          {active === 2 && <section>
            <h2 className="section-title">Appearance</h2>
          </section>}
          {active === 3 && <section>
            <h2 className="section-title">App Activity</h2>
          </section>}
          {active === 4 && <section>
            <h2 className="section-title">Change Log</h2>
          </section>}
        </div>
      </div>
    )
  }
}

export default Settings;