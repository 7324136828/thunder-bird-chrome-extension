import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { initBackendBase, watchBackendBase } from './platform/backend';
import './styles.css';

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Could not find the root element.');
}

// Every backend call uses the configured base URL, so resolve it first.
void initBackendBase().then(() => {
  // A new backend has different accounts and sessions: start over.
  watchBackendBase(() => window.location.reload());
  createRoot(rootElement).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});
