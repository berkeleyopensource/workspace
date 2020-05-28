import React from 'react';
import Navbar from "./components/Navbar";
import './SignInUp.css';
import { RouteComponentProps } from "react-router-dom";

class EmailVerify extends React.Component<RouteComponentProps, any> {
  constructor(props: any) {
    super(props);
  }
  componentDidMount() {
    const params = new URLSearchParams(this.props.location.search),
      token = params.get("token"), invalid = params.get("invalid");

    console.log(token, invalid);
    fetch('http://xxx/api/verify', { method: 'POST', body: JSON.stringify({token, invalid})})
      .then(resp => console.log(resp)).catch(error => console.log(error));

  }
  render() {
    return (
      <div className="SignInUp">
        <Navbar/>
        <div></div>
      </div>
    )
  }
}

export default EmailVerify;