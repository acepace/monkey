import React from 'react';
import AuthService from '../services/AuthService';

class AuthComponent extends React.Component {
  constructor(props) {
    super(props);
    this.auth = new AuthService();
    this.authFetch = this.auth.authFetch;
    this.jwtHeader = this.auth.jwtHeader();
  }
}

export function authFetch(){
  const auth = new AuthService();
  const authFetch = auth.authFetch;
  const jwtHeader = auth.jwtHeader();
}

export default AuthComponent;
