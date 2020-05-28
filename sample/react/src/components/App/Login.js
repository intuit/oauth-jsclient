import React, { useState, useEffect, useContext } from 'react';
import { Redirect } from 'react-router-dom';
import { AuthContext } from '../../App';
import { LoginWrapper } from '../shared/LoginWrapper';

export default function Login() {
  const { state, dispatch } = useContext(AuthContext);
  const [data, setData] = useState({ errorMessage: '', isLoading: false });

  const { authorize_url } = state;

  useEffect(() => {
    const url = window.location.href;
    const hasCode = url.includes('?code=');

    if (hasCode) {
      const newUrl = url.split('?code=');
      window.history.pushState({}, null, newUrl[0]);
      setData({ ...data, isLoading: true });

      const requestData = {
        client_id: state.client_id,
        redirect_uri: state.redirect_uri,
        client_secret: state.client_secret,
        code: newUrl[1],
        url: url,
      };
      const proxy_url = state.proxy_url;

      fetch(proxy_url, {
        method: 'POST',
        body: JSON.stringify(requestData),
      })
        .then((response) => response.json())
        .then((data) => {
          dispatch({
            type: 'LOGIN',
            payload: { user: data, isLoggedIn: true },
          });
        })
        .catch((error) => {
          setData({
            isLoading: false,
            errorMessage: 'Sorry! Login failed',
          });
        });
    }
  }, [state, dispatch, data]);

  if (state.isLoggedIn) {
    return <Redirect to="/" />;
  }

  const buttonClicked = () => {
    fetch(authorize_url)
      .then((res) => res.text())
      .then((url) => {
        window.location.href = url;
      });
  };

  return (
    <LoginWrapper>
      <section className="container">
        <div>
          <h1>OAuth2.0 using React</h1>
          <span>
            <a
              target="_blank"
              rel="noopener noreferrer"
              href="https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0#obtain-oauth2-credentials-for-your-app"
            >
              Documentation
            </a>
          </span>
          <span>{data.errorMessage}</span>
          <div className="login-container">
            {data.isLoading ? (
              <div className="loader-container">
                <div className="loader"></div>
              </div>
            ) : (
              <>
                <button
                  className="login-link"
                  onClick={() => {
                    buttonClicked();
                    setData({ ...data, errorMessage: '' });
                  }}
                >
                  <img
                    src="/C2QB_green_btn_lg_default.png"
                    width="178"
                    alt="connect_to_quickbooks"
                  />
                </button>
              </>
            )}
          </div>
        </div>
      </section>
    </LoginWrapper>
  );
}
