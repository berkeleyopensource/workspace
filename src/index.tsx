import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';

import SignIn from "./SignIn";
import SignUp from "./SignUp";
import * as serviceWorker from './serviceWorker';

import { HashRouter, Route } from "react-router-dom";

ReactDOM.render(
  <HashRouter>
    <div>
      <Route path="/" exact component={ SignIn } />
      <Route path="/signin" component={ SignIn } />
      <Route path="/signup" component={ SignUp } />
      <Route path="/channels/:channel" component={ SignUp } />
    </div>
  </HashRouter>,
  document.getElementById('root')
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
