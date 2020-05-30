import { Dispatch } from 'redux';

export const userSignin = (body: string) => {
  return async (dispatch: Dispatch<any>) => {
    let resp = await fetch("http://api.arifulrigan.com/api/signin", {method: 'POST', mode: 'cors', credentials: 'include', body})
    if (resp.ok) { dispatch({type: "setState", key: 'authState', value: true})
    } else { dispatch({type: "setState", key: 'authState', value: false}) }
    return resp;
  }
}

export const userSignup = (body: string) => {
  return async (dispatch: Dispatch<any>) => {
    let resp = await fetch("http://api.arifulrigan.com/api/signup", {method: 'POST', mode: 'cors', credentials: 'include', body})
    if (resp.ok) { dispatch({type: "setState", key: 'authState', value: true})
    } else { dispatch({type: "setState", key: 'authState', value: false}) }
    return resp;
  }
}

export const tokenRefresh = () => {
  return async (dispatch: Dispatch<any>) => {
    let resp = await fetch("http://api.arifulrigan.com/api/refresh", {method: 'POST',  mode: 'cors', credentials: 'include'})
    if (resp.ok) { dispatch({type: "setState", key: 'authState', value: true})
    } else { dispatch({type: "setState", key: 'authState', value: false}) }
    return resp;
  }
}