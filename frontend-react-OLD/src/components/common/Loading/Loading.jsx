/* ==========================================
   NGCORION - Loading Component
   ========================================== */

import './Loading.css';

const Loading = ({ size = 'medium', text = 'Loading...' }) => {
  return (
    <div className={`loading loading-${size}`}>
      <div className="loading-spinner" />
      {text && <span className="loading-text">{text}</span>}
    </div>
  );
};

export default Loading;
