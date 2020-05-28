import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';

import Landing from "./views/Landing";
import SignIn from "./views/SignIn";
import SignUp from "./views/SignUp";
import PasswordReset from "./views/PasswordReset"

import Workspace from "./views/Workspace";
import Settings from "./views/Settings";
import EmailVerify from "./views/EmailVerify";
import NotFound from "./views/NotFound";

import * as serviceWorker from './serviceWorker';

import { BrowserRouter, Route, Switch } from "react-router-dom";

ReactDOM.render(
  <BrowserRouter>
    <Switch>
      <Route path="/signin" component={ SignIn }/>
      <Route path="/signup" component={ SignUp }/>
      <Route path="/reset" component={ PasswordReset }/>
      <Route path="/verify" component={ EmailVerify }/>
      <Route path="/workspace" component={ Workspace }/>
      <Route path="/settings" component={ Settings }/>
      <Route path="/" exact component={ Landing }/>
      <Route component={ NotFound }/>
    </Switch>
  </BrowserRouter>,
  document.getElementById('root')
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
