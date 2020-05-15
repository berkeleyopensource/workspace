import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';

import SignIn from "./views/SignIn";
import SignUp from "./views/SignUp";
import PasswordReset from "./views/PasswordReset"

import Workspace from "./views/Workspace";
import Settings from "./views/Settings";
import EmailVerify from "./views/EmailVerify";

import * as serviceWorker from './serviceWorker';

import { BrowserRouter, Route } from "react-router-dom";

ReactDOM.render(
  <BrowserRouter>
    <div>
      <Route path="/" exact component={ EmailVerify } />
      <Route path="/signin" component={ SignIn } />
      <Route path="/signup" component={ SignUp } />
      <Route path="/workspace" component={ Workspace } />
      <Route path="/settings" component={ Settings } />
      <Route path="/reset" component={ PasswordReset } />
      <Route path="/verify" component={ EmailVerify } />
    </div>
  </BrowserRouter>,
  document.getElementById('root')
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
