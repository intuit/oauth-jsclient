import Styled from 'styled-components';

export const LoginWrapper = Styled.section`
.container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  font-family: MMA Champ;
  
  > div:nth-child(1) {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    box-shadow: 0 15px 30px 0 rgba(0,0,0,.11), 0 5px 15px 0 rgba(0,0,0,.08);
    transition: 0.3s;
    width: 25%;
    height: 45%;
    > h1 {
      font-size: 2rem;
      margin-bottom: 20px;
    }
    > span:nth-child(2) {
      font-size: 1.1rem;
      color: #808080;
      margin-bottom: 30px;
    }
    > span:nth-child(3) {
      margin: 10px 0 20px;
      color: red;
    }
    .login-container {
      background-color: #000;
      width: 40%;
      border-radius: 3px;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      > .login-link {
        text-decoration: none;
        color: #fff;
        text-transform: uppercase;
        cursor: pointer;
        display: flex;
        align-items: center;          
        // height: 40px;
        > span:nth-child(2) {
          margin-left: 5px;
        }
      }
      .loader-container {
        display: flex;
        justify-content: center;
        align-items: center;          
        height: 40px;
      }
      .loader {
        border: 4px solid #f3f3f3;
        border-top: 4px solid #3498db;
        border-radius: 50%;
        width: 12px;
        height: 12px;
        animation: spin 2s linear infinite;
      }
      @keyframes spin {
        0% {
          transform: rotate(0deg);
        }
        100% {
          transform: rotate(360deg);
        }
      }
    }
  }
}
`;
