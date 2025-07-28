import React from 'react';
import ReactDOM from 'react-dom/client';
import './styles/index.css';
import InnerOdysseyApp from './inner-odyssey-kids';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

root.render(
  <React.StrictMode>
    <InnerOdysseyApp />
  </React.StrictMode>
);