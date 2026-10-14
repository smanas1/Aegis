import React, { useState, useRef, useEffect } from 'react';
import {
  UploadCloud,
  ShieldAlert,
  ShieldCheck,
  Download,
  Sparkles,
  RefreshCw,
  FileCode,
  Sliders,
  CheckCircle2,
  AlertOctagon,
  Eye,
  Layers,
  ArrowRight,
  Zap,
  Info
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { scanImageMetadata } from '../utils/metadataScanner';
import { sanitizeImage } from '../utils/imageSanitizer';
import { createSampleAIImage } from '../utils/sampleAssets';

export default function ImageStripper() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isSanitizing, setIsSanitizing] = useState(false);
  const [sanitizedResult, setSanitizedResult] = useState(null);

  // Settings
  const [outputFormat, setOutputFormat] = useState('image/png');
  const [antiFingerprint, setAntiFingerprint] = useState(true);
  const [quality, setQuality] = useState(0.96);
  const [viewMode, setViewMode] = useState('split'); // 'split' | 'before' | 'after'

  const fileInputRef = useRef(null);

  // Handle file drop & selection
  const handleFileChange = async (file) => {
    if (!file || !file.type.startsWith('image/')) {
      alert('Please select a valid image file (PNG, JPEG, WebP).');
      return;
    }

    setSelectedFile(file);
    setSanitizedResult(null);
    setIsScanning(true);

    const objectUrl = URL.createObjectURL(file);
    setPreviewUrl(objectUrl);

    try {
      const audit = await scanImageMetadata(file);
      setScanResult(audit);
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  // Support paste from clipboard
  useEffect(() => {
    const handlePaste = (e) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      for (let i = 0; i < items.length; i++) {
        if (items[i].type.indexOf('image') !== -1) {
          const file = items[i].getAsFile();
          handleFileChange(file);
          break;
        }
      }
    };
    window.addEventListener('paste', handlePaste);
    return () => window.removeEventListener('paste', handlePaste);
  }, []);

  // Load preset sample
  const handleLoadSample = async () => {
    setIsScanning(true);
    try {
      const sampleFile = await createSampleAIImage();
      await handleFileChange(sampleFile);
    } catch (e) {
      console.error(e);
    } finally {
      setIsScanning(false);
    }
  };

  // Run Sanitization
  const handleSanitize = async () => {
    if (!selectedFile) return;
    setIsSanitizing(true);

    try {
      const result = await sanitizeImage(selectedFile, {
        outputFormat,
        quality,
        antiFingerprint
      });

      setSanitizedResult(result);

      // Trigger celebratory micro-animation
      confetti({
        particleCount: 50,
        spread: 60,
        origin: { y: 0.7 },
        colors: ['#00f0ff', '#8b5cf6', '#10b981']
      });
    } catch (err) {
      console.error('Sanitize error:', err);
      alert('Failed to clean image: ' + err.message);
    } finally {
      setIsSanitizing(false);
    }
  };

  // Download cleaned file
  const handleDownload = () => {
    if (!sanitizedResult) return;
    const link = document.createElement('a');
    link.href = sanitizedResult.cleanedUrl;

    const ext = outputFormat === 'image/jpeg' ? 'jpg' : outputFormat === 'image/webp' ? 'webp' : 'png';
    const originalName = selectedFile ? selectedFile.name.replace(/\.[^/.]+$/, '') : 'cleaned_image';
    link.download = `${originalName}_ghost_clean.${ext}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="section-container">
      {/* Hero Header */}
      <div className="section-hero">
        <div className="badge-pill">
          <Zap size={14} className="accent-cyan" />
          <span>Platform AI Badge Neutralizer</span>
        </div>
        <h1 className="hero-title">
          Eradicate AI Metadata & <span className="gradient-text">C2PA Provenance</span>
        </h1>
        <p className="hero-subtitle">
          Strip DALL·E, Midjourney, Imagen, and ComfyUI manifests. Neutralize LinkedIn & Meta "Created with AI" badges, purge IPTC source tags, and scramble Google SynthID watermarks.
        </p>
      </div>

      {/* Main Grid */}
      <div className="image-stripper-grid">
        {/* Left Column: Upload & Options */}
        <div className="panel upload-panel">
          <div className="panel-header">
            <div className="panel-title">
              <UploadCloud size={20} className="accent-cyan" />
              <span>1. Import AI-Generated Image</span>
            </div>
            <button
              id="btn-load-sample-image"
              className="btn-ghost-sm"
              onClick={handleLoadSample}
              disabled={isScanning || isSanitizing}
              title="Test with a simulated DALL-E image with real C2PA chunk"
            >
              <Sparkles size={14} />
              <span>Load AI Sample</span>
            </button>
          </div>

          {/* Drag & Drop Box */}
          <div
            id="drop-zone-image"
            className={`drop-zone ${selectedFile ? 'has-file' : ''}`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => {
              e.preventDefault();
              e.stopPropagation();
            }}
            onDrop={(e) => {
              e.preventDefault();
              e.stopPropagation();
              if (e.dataTransfer.files?.[0]) {
                handleFileChange(e.dataTransfer.files[0]);
              }
            }}
          >
            <input
              type="file"
              ref={fileInputRef}
              style={{ display: 'none' }}
              accept="image/png, image/jpeg, image/webp"
              onChange={(e) => e.target.files?.[0] && handleFileChange(e.target.files[0])}
            />

            {!selectedFile ? (
              <div className="drop-zone-prompt">
                <div className="upload-icon-circle">
                  <UploadCloud size={32} />
                </div>
                <div className="drop-title">Drag & drop your AI image here</div>
                <div className="drop-subtitle">or click to browse from device (Ctrl+V paste supported)</div>
                <div className="drop-tags">
                  <span className="tag">PNG (c2pa)</span>
                  <span className="tag">JPEG (APP11 JUMBF)</span>
                  <span className="tag">WebP</span>
                </div>
              </div>
            ) : (
              <div className="selected-file-info">
                <div className="file-preview-mini">
                  <img src={previewUrl} alt="Thumbnail preview" />
                </div>
                <div className="file-details">
                  <div className="file-name" title={selectedFile.name}>{selectedFile.name}</div>
                  <div className="file-meta">
                    {(selectedFile.size / 1024).toFixed(1)} KB • {scanResult?.format || selectedFile.type}
                  </div>
                  <div className="file-replace">Click or drop to replace image</div>
                </div>
              </div>
            )}
          </div>

          {/* Sanitization Config Settings */}
          <div className="config-box">
            <div className="config-header">
              <Sliders size={16} />
              <span>Sanitization Settings</span>
            </div>

            <div className="config-item">
              <label>Output Clean Format</label>
              <div className="format-options">
                {['image/png', 'image/jpeg', 'image/webp'].map((fmt) => (
                  <button
                    key={fmt}
                    id={`btn-fmt-${fmt.split('/')[1]}`}
                    className={`btn-toggle-option ${outputFormat === fmt ? 'active' : ''}`}
                    onClick={() => setOutputFormat(fmt)}
                  >
                    {fmt.split('/')[1].toUpperCase()}
                    {fmt === 'image/png' && <span className="mini-badge">Lossless</span>}
                  </button>
                ))}
              </div>
            </div>

            {outputFormat !== 'image/png' && (
              <div className="config-item">
                <div className="slider-label">
                  <span>Compression Quality: {Math.round(quality * 100)}%</span>
                  <span className="slider-hint">Ultra-clean visual preservation</span>
                </div>
                <input
                  type="range"
                  min="0.80"
                  max="1.00"
                  step="0.02"
                  value={quality}
                  onChange={(e) => setQuality(parseFloat(e.target.value))}
                  className="quality-slider"
                />
              </div>
            )}

            <div className="config-item toggle-row">
              <div className="toggle-info">
                <div className="toggle-title">
                  <span>Anti-Fingerprint Cloak (SynthID Disrupter)</span>
                  <span className="badge-recommend">Recommended</span>
                </div>
                <p className="toggle-desc">
                  Applies imperceptible ±1 LSB micro-dithering to neutralize mathematical frequency watermarks (Google SynthID / Fourier watermarks) without altering human vision.
                </p>
              </div>
              <label className="switch">
                <input
                  id="toggle-anti-fingerprint"
                  type="checkbox"
                  checked={antiFingerprint}
                  onChange={(e) => setAntiFingerprint(e.target.checked)}
                />
                <span className="slider-switch round"></span>
              </label>
            </div>
          </div>

          {/* Action Button */}
          <button
            id="btn-sanitize-image"
            className="btn-primary-action"
            disabled={!selectedFile || isScanning || isSanitizing}
            onClick={handleSanitize}
          >
            {isSanitizing ? (
              <>
                <RefreshCw size={18} className="spin" />
                <span>Sanitizing Raw Pixels...</span>
              </>
            ) : (
              <>
                <Sparkles size={18} />
                <span>Purge AI Provenance & Clean Image</span>
              </>
            )}
          </button>
        </div>

        {/* Right Column: Audit, Inspection & Download */}
        <div className="panel preview-panel">
          <div className="panel-header">
            <div className="panel-title">
              <Eye size={20} className="accent-violet" />
              <span>2. Provenance Audit & Verification</span>
            </div>
            {sanitizedResult && (
              <div className="view-mode-tabs">
                <button
                  className={`btn-subtab ${viewMode === 'split' ? 'active' : ''}`}
                  onClick={() => setViewMode('split')}
                >
                  Side by Side
                </button>
                <button
                  className={`btn-subtab ${viewMode === 'after' ? 'active' : ''}`}
                  onClick={() => setViewMode('after')}
                >
                  Clean Result
                </button>
              </div>
            )}
          </div>

          {/* Visual Display */}
          <div className="display-canvas-area">
            {!previewUrl ? (
              <div className="empty-state">
                <Layers size={48} className="empty-icon" />
                <h3>No Image Loaded</h3>
                <p>Import an image on the left or click "Load AI Sample" to run the provenance vulnerability scan.</p>
              </div>
            ) : (
              <div className="image-comparison-wrapper">
                {viewMode === 'split' && sanitizedResult ? (
                  <div className="split-view">
                    <div className="image-frame">
                      <div className="frame-tag original-tag">Original (Dirty)</div>
                      <img src={previewUrl} alt="Original with AI metadata" />
                    </div>
                    <div className="image-frame">
                      <div className="frame-tag clean-tag">Ghost Clean (Purged)</div>
                      <img src={sanitizedResult.cleanedUrl} alt="Cleaned without metadata" />
                    </div>
                  </div>
                ) : (
                  <div className="single-view">
                    <img
                      src={sanitizedResult ? sanitizedResult.cleanedUrl : previewUrl}
                      alt="Active preview"
                    />
                    {sanitizedResult && (
                      <div className="verified-overlay-pill">
                        <CheckCircle2 size={16} />
                        <span>100% Provenance Sterilized</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Audit Results Bar */}
          {scanResult && (
            <div className="audit-section">
              <div className="audit-header">
                <div className="audit-title-block">
                  <h4>Vulnerability Audit</h4>
                  <span className={`risk-badge risk-${sanitizedResult ? 'SAFE' : scanResult.riskLevel}`}>
                    {sanitizedResult ? '100% SAFE (PURGED)' : `${scanResult.riskLevel} RISK`}
                  </span>
                </div>
                <div className="platform-badges-row">
                  <span
                    className={`platform-pill ${
                      sanitizedResult ? 'safe' : scanResult.platformBadgeRisk.linkedIn ? 'danger' : 'safe'
                    }`}
                  >
                    LinkedIn Badge: {sanitizedResult ? 'Bypassed' : scanResult.platformBadgeRisk.linkedIn ? 'Triggered!' : 'Clean'}
                  </span>
                  <span
                    className={`platform-pill ${
                      sanitizedResult ? 'safe' : scanResult.platformBadgeRisk.metaInstagram ? 'danger' : 'safe'
                    }`}
                  >
                    Meta "AI Info": {sanitizedResult ? 'Bypassed' : scanResult.platformBadgeRisk.metaInstagram ? 'Triggered!' : 'Clean'}
                  </span>
                </div>
              </div>

              {/* Items checklist */}
              <div className="audit-checklist">
                <div className="audit-row">
                  <span className="audit-label">C2PA Manifest (Content Credentials):</span>
                  {sanitizedResult ? (
                    <span className="audit-status safe">
                      <CheckCircle2 size={15} /> 0 bytes (Purged)
                    </span>
                  ) : scanResult.hasC2PA ? (
                    <span className="audit-status danger">
                      <AlertOctagon size={15} /> DETECTED ({scanResult.c2paManifestInfo?.chunk || 'Active'})
                    </span>
                  ) : (
                    <span className="audit-status safe">
                      <CheckCircle2 size={15} /> Not Present
                    </span>
                  )}
                </div>

                <div className="audit-row">
                  <span className="audit-label">IPTC digitalSourceType:</span>
                  {sanitizedResult ? (
                    <span className="audit-status safe">
                      <CheckCircle2 size={15} /> Cleared
                    </span>
                  ) : scanResult.aiSignaturesFound.some((s) => s.includes('trainedAlgorithmicMedia')) ? (
                    <span className="audit-status danger">
                      <AlertOctagon size={15} /> trainedAlgorithmicMedia
                    </span>
                  ) : (
                    <span className="audit-status safe">
                      <CheckCircle2 size={15} /> Clean
                    </span>
                  )}
                </div>

                <div className="audit-row">
                  <span className="audit-label">EXIF & Generative Prompts:</span>
                  {sanitizedResult ? (
                    <span className="audit-status safe">
                      <CheckCircle2 size={15} /> 0 EXIF bytes
                    </span>
                  ) : scanResult.hasAIPrompts || scanResult.hasEXIF ? (
                    <span className="audit-status warning">
                      <ShieldAlert size={15} /> Prompts / EXIF Found
                    </span>
                  ) : (
                    <span className="audit-status safe">
                      <CheckCircle2 size={15} /> Clean
                    </span>
                  )}
                </div>

                <div className="audit-row">
                  <span className="audit-label">SynthID / Frequency Fingerprint:</span>
                  {sanitizedResult ? (
                    <span className="audit-status safe">
                      <CheckCircle2 size={15} /> {antiFingerprint ? 'Scrambled & Neutralized' : 'Pure Re-encode'}
                    </span>
                  ) : (
                    <span className="audit-status warning">
                      <Info size={15} /> Potentially Present
                    </span>
                  )}
                </div>
              </div>

              {/* Signatures List if found */}
              {!sanitizedResult && scanResult.aiSignaturesFound.length > 0 && (
                <div className="signatures-detected-box">
                  <div className="sig-header">
                    <ShieldAlert size={14} />
                    <span>Identified AI Provenance Markers:</span>
                  </div>
                  <ul>
                    {scanResult.aiSignaturesFound.map((sig, idx) => (
                      <li key={idx}>{sig}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Download Action Bar */}
          {sanitizedResult && (
            <div className="download-action-bar">
              <div className="download-stats">
                <span className="stat-clean-size">
                  Clean File: {(sanitizedResult.cleanedSize / 1024).toFixed(1)} KB
                </span>
                <span className="stat-savings">
                  All AI Tracking Purged
                </span>
              </div>
              <button
                id="btn-download-clean-image"
                className="btn-download-large"
                onClick={handleDownload}
              >
                <Download size={18} />
                <span>Download Safe Clean Image</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
