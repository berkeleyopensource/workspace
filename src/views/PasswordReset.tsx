import React from 'react';
import { Link, RouteComponentProps } from 'react-router-dom';

import Navbar from "./components/Navbar";
import './SignInUp.css';

interface FormState {
  errors: { email: String, password: String, [key: string]: any },
  token: String,
  valid: Boolean,
}

class PasswordReset extends React.Component<RouteComponentProps, FormState> {
  constructor(props: any) {
    super(props);
    this.state = {errors: {email: "", password: ""}, token: "", valid: true};
  }
  
  handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const form = event.target as HTMLFormElement,
      email = form.email.value;
    
    const { errors } = this.state;
    // TODO: hook this up to backend api.

    fetch('http://xxx/api/reset', {
      method: 'POST',
      body: JSON.stringify({email}),
    }).then(resp => console.log(resp)).catch(error => console.log(error));

    this.setState({errors});
  }
  handleChange = (event: React.FormEvent<HTMLInputElement>) => {
    const input = event.target as HTMLInputElement;
    const { errors } = this.state;
    errors[input.name] = "";
    this.setState({errors});
  }

  componentDidMount() {
    const params = new URLSearchParams(this.props.location.search),
      token = params.get("token") || "", valid = params.get("valid") ? true : false;
    this.setState({token: token, valid: valid});
  }

  render() {
    return (
      <div className="SignInUp">
        <Navbar/>
        <form onSubmit={this.handleSubmit}>
          { this.state.token == ""
            ? <div>
                <h2>Reset your password.</h2>
                <div className={"input-group " + (this.state.errors.email ? "input-error" : "")}>
                  <div className="input-title">
                    Email Address {this.state.errors.email ? <span>- {this.state.errors.email}</span> : ""}
                  </div>
                  <input type="email" name="email" onChange={this.handleChange} required></input>
                </div>
              </div>
            : <div>
                <h2>Enter a new password.</h2>
                <div className={"input-group " + (this.state.errors.password ? "input-error" : "")}>
                  <div className="input-title">
                    Password {this.state.errors.password ? <span>- {this.state.errors.password}</span> : ""}
                  </div>
                  <input type="password" name="password" onChange={this.handleChange} required></input>
                </div>              
              </div>
          }
          <div className="input-group">
            <button className="button-primary" type="submit">
              <div>Continue</div>
            </button>
          </div>
          <div className="input-group">
            <div>Need an account? <Link to="/signup">Register.</Link></div>
            <div>Already have an account? <Link to="/signin">Sign in.</Link></div>
          </div>
        </form>
      </div>
    )
  }
}

export default PasswordReset;