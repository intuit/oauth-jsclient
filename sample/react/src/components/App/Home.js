import React, { useContext } from 'react';
import { Redirect } from 'react-router-dom';
import { AuthContext } from '../../App';
import { HomeWrapper } from '../shared/HomeWrapper';

export default function Home() {
  const { state, dispatch } = useContext(AuthContext);

  if (!state.isLoggedIn) {
    return <Redirect to="/login" />;
  }

  const { givenName, familyName, email, phoneNumber } = state.user.userInfo;
  const { CompanyName, LegalName, Email, Country } = state.user.companyInfo.CompanyInfo;

  const handleLogout = () => {
    dispatch({
      type: 'LOGOUT',
    });
  };

  return (
    <HomeWrapper>
      <div className="container">
        <button onClick={() => handleLogout()}>Logout</button>
        <div>
          <div className="content">
            <img src={'/user-info.png'} alt="alt_avatar" />
            <span>
              <h2>User Info</h2>
            </span>
            <span>
              <strong>Given Name : </strong>
              {givenName}
            </span>
            <span>
              <strong>Family Name : </strong>
              {familyName}
            </span>
            <span>
              <strong>Email : </strong>
              {email}
            </span>
            <span>
              <strong>Phone Number : </strong>
              {phoneNumber}
            </span>
          </div>
          <div className="content">
            <img src={'/company-info.png'} alt="alt_avatar" />
            <span>
              <h2>Company Info</h2>
            </span>
            <span>
              <strong>Company Name : </strong>
              {CompanyName}
            </span>
            <span>
              <strong>Legal Name : </strong>
              {LegalName}
            </span>
            <span>
              <strong>Company Email : </strong>
              {Email.Address}
            </span>
            <span>
              <strong>Locale : </strong>
              {Country}
            </span>
          </div>
        </div>
      </div>
    </HomeWrapper>
  );
}
