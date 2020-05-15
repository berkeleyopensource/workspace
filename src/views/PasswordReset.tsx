import React from 'react';
import { Link } from 'react-router-dom';
import Navbar from "./components/Navbar";
import './SignInUp.css';

interface FormState {
  errors: { email: String, [key: string]: any }
}

class PasswordReset extends React.Component<any, FormState> {
  constructor(props: any) {
    super(props);
    this.state = {errors: {email: ""}};
  }
  handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const form = event.target as HTMLFormElement,
      email = form.email.value;
    
    const { errors } = this.state;
    // TODO: hook this up to backend api.
    errors.email = "This email has already been used.";

    fetch('http://xxx/api/signup', {
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
  render() {
    const { errors } = this.state;
    return (
      <div className="SignInUp">
        <Navbar/>
        <form onSubmit={this.handleSubmit}>
          <h2>Reset your password.</h2>
          <div className={"input-group " + (errors.email ? "input-error" : "")}>
            <div className="input-title">
              Email Address {errors.email ? <span>- {errors.email}</span> : ""}
            </div>
            <input type="email" name="email" onChange={this.handleChange} required></input>
          </div>
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