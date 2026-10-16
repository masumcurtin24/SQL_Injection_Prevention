// frontend/src/main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.tsx';
import './index.css'; // Your global CSS with Tailwind directives

// Import your context providers
import { NotificationProvider } from './contexts/NotificationContext.tsx';

const rootElement = document.getElementById('root');

if (rootElement) {
  const appTree = (
    <NotificationProvider>
      <App />
    </NotificationProvider>
  );

  ReactDOM.createRoot(rootElement).render(
    import.meta.env.DEV ? appTree : <React.StrictMode>{appTree}</React.StrictMode>,
  );
} 
else {
  console.error("Failed to find the root element. Ensure your index.html has a div with id='root'.");
}
