import React from 'react';
import { Shield, Image as ImageIcon, FileText, Info, Sparkles, Lock } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, onOpenExplainer }) {
  return (
    <header className="navbar">
      <div className="navbar-container">
        <div className="brand" onClick={() => setActiveTab('image')}>
          <div className="brand-logo-glow">
            <Shield className="brand-icon" size={26} />
          </div>
          <div className="brand-text">
            <div className="brand-title">
              GhostMeta<span className="brand-badge">AI</span>
            </div>
            <div className="brand-subtitle">AI Provenance & Watermark Purger</div>
          </div>
        </div>

        <nav className="tab-nav">
          <button
            id="tab-btn-image"
            className={`tab-btn ${activeTab === 'image' ? 'active' : ''}`}
            onClick={() => setActiveTab('image')}
          >
            <ImageIcon size={18} />
            <span>Phase 1: Image Purger</span>
            <span className="pill-pulse">C2PA / EXIF / SynthID</span>
          </button>

          <button
            id="tab-btn-text"
            className={`tab-btn ${activeTab === 'text' ? 'active' : ''}`}
            onClick={() => setActiveTab('text')}
          >
            <FileText size={18} />
            <span>Phase 2: Text Humanizer</span>
            <span className="pill-pulse">Unicode / Cliché Buster</span>
          </button>
        </nav>

        <div className="navbar-actions">
          <div className="privacy-badge" title="100% Client-Side. Your images and text never leave your device.">
            <Lock size={14} />
            <span>100% Private Client-Side</span>
          </div>

          <button
            id="btn-how-it-works"
            className="btn-explainer"
            onClick={onOpenExplainer}
            title="Learn how LinkedIn, Meta, and Google detect AI content"
          >
            <Info size={16} />
            <span>How AI Detection Works</span>
          </button>
        </div>
      </div>
    </header>
  );
}
