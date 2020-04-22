import React from 'react';
import './SignInUp.css';

import { Link } from 'react-router-dom';

interface FormState {
  errors: { email: String, password: String, [key: string]: any }
}

class SignIn extends React.Component<any, FormState> {
  constructor(props: any) {
    super(props);
    this.state = {errors: {email: "", password: ""}};
  }
  handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const form = event.target as HTMLFormElement,
      email = form.email.value, password = form.password.value;
    
    const { errors } = this.state;
    // TODO: hook this up to backend api.
    errors.email = "This email has already been used.";

    this.setState({errors});
  }
  handleChange = (event: React.FormEvent<HTMLInputElement>) => {
    const input = event.target as HTMLInputElement;
    const { errors } = this.state;
    errors[input.name] = "";
    this.setState({errors});
  }
  render() {
    const { errors } = this.state;
    return (
      <div className="SignInUp">
        <nav>
          <h2>workspace</h2>
        </nav>
        <form onSubmit={this.handleSubmit}>
          <h2>Sign in.</h2>
          <div className={"input-group " + (errors.email ? "input-error" : "")}>
            <div className="input-title">
              Email Address {errors.email ? <span>- {errors.email}</span> : ""}
            </div>
            <input type="email" name="email" onChange={this.handleChange} required></input>
          </div>
          <div className={"input-group " + (errors.password ? "input-error" : "")}>
            <div className="input-title">
              Password {errors.password ? <span>- {errors.password}</span> : ""}
            </div>
            <input type="password" name="password" onChange={this.handleChange} required></input>
          </div>
          <div className="input-group">
            <button className="button-primary" type="submit">
              <div>Continue</div>
            </button>
          </div>
          <div className="input-group">
            <div><Link to="/reset">Forgot your password?</Link></div>
            <div>Need an account? <Link to="/signup">Register.</Link></div>
          </div>
        </form>
      </div>
    )
  }
}

export default SignIn;