import React from 'react';
import { Link } from 'react-router-dom';
import Navbar from "./components/Navbar";
import './SignInUp.css';

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
    
    fetch('http://api.arifulrigan.com/api/signin', { method: 'POST', body: JSON.stringify({email, password})})
      .then(resp => resp.ok ? this.props.history.push("/") : this.handleErrors(resp, form));
  }

  handleChange = (event: React.FormEvent<HTMLInputElement>) => {
    const input = event.target as HTMLInputElement;
    const { errors } = this.state;
    errors[input.name] = "";
    this.setState({errors});
  }

  handleErrors = (response: any, form: HTMLFormElement) => {
    const { errors } = this.state;
    errors.email = ""; errors.password = "";

    response.text().then((error: String) => {
      switch (response.status) {
        case 404: 
          errors.email = error;
          form.email.focus()
          break;
        case 401:
          errors.password = error;
          form.password.focus()
          break;
      }
      this.setState({errors});
    })
    
  }

  render() {
    const { errors } = this.state;
    return (
      <div className="SignInUp">
        <Navbar/>
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