import React from 'react';
import { X, ShieldCheck, AlertTriangle, Eye, Cpu, Database, Fingerprint } from 'lucide-react';

export default function DetectionExplainerModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-wrap">
            <div className="modal-icon-badge">
              <Eye size={22} />
            </div>
            <div>
              <h3>How Platforms Detect AI & How GhostMeta Defeats Them</h3>
              <p className="modal-sub">LinkedIn, Meta (Instagram/Facebook), and Google Provenance Deep Dive</p>
            </div>
          </div>
          <button className="btn-close" onClick={onClose} id="btn-close-modal">
            <X size={20} />
          </button>
        </div>

        <div className="modal-body">
          <div className="explainer-grid">
            {/* C2PA Section */}
            <div className="explainer-card">
              <div className="card-top">
                <ShieldCheck className="accent-cyan" size={20} />
                <h4>1. C2PA Content Credentials</h4>
              </div>
              <p>
                <strong>Who uses it:</strong> OpenAI (DALL·E 3), Adobe Firefly, Microsoft Designer, Leica.
              </p>
              <p>
                <strong>How platforms detect it:</strong> LinkedIn and Meta read cryptographic manifest chunks (<code>c2pa</code> chunk in PNG or <code>APP11 / JUMBF</code> in JPEG). If present, LinkedIn immediately slaps the "Created with AI" badge.
              </p>
              <div className="solution-badge">
                <Cpu size={14} />
                <span><strong>GhostMeta Solution:</strong> Pure raw pixel regeneration extracts raw RGBA buffers and builds a virgin clean container, eradicating 100% of C2PA manifests.</span>
              </div>
            </div>

            {/* IPTC / XMP Section */}
            <div className="explainer-card">
              <div className="card-top">
                <Database className="accent-violet" size={20} />
                <h4>2. IPTC & XMP Digital Source Tags</h4>
              </div>
              <p>
                <strong>Who uses it:</strong> Midjourney, DALL-E, Stable Diffusion, ComfyUI, Photoshop.
              </p>
              <p>
                <strong>How platforms detect it:</strong> Standard IPTC tag <code>Iptc4xmpExt:DigitalSourceType</code> set to <code>http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia</code> or software headers containing model seeds.
              </p>
              <div className="solution-badge">
                <Cpu size={14} />
                <span><strong>GhostMeta Solution:</strong> Zero-tolerance header purge. EXIF, IPTC, and XMP blocks are completely stripped.</span>
              </div>
            </div>

            {/* Google SynthID Section */}
            <div className="explainer-card">
              <div className="card-top">
                <Fingerprint className="accent-emerald" size={20} />
                <h4>3. Google SynthID (Pixel Watermark)</h4>
              </div>
              <p>
                <strong>Who uses it:</strong> Google Imagen 3 / Gemini.
              </p>
              <p>
                <strong>How platforms detect it:</strong> Imperceptible statistical correlations embedded across spatial and frequency Fourier domains that survive typical resizing and compression.
              </p>
              <div className="solution-badge">
                <Cpu size={14} />
                <span><strong>GhostMeta Solution:</strong> Anti-Fingerprint Cloak applies an imperceptible pseudo-random micro-perturbation (±1 LSB) to scramble frequency coherence without degrading human-visible visual crispness.</span>
              </div>
            </div>

            {/* Text Watermarks Section */}
            <div className="explainer-card">
              <div className="card-top">
                <AlertTriangle className="accent-amber" size={20} />
                <h4>4. Zero-Width Unicode & AI Text Stylometry</h4>
              </div>
              <p>
                <strong>Who uses it:</strong> LLM watermarking research, Turnitin, Copyleaks, GPTZero.
              </p>
              <p>
                <strong>How platforms detect it:</strong> Invisible zero-width spaces (<code>\u200B</code>, <code>\u200D</code>, <code>\uFEFF</code>) embedded between words, flat sentence length variance (low burstiness), and robotic clichés like <em>"delve into the vibrant tapestry"</em>.
              </p>
              <div className="solution-badge">
                <Cpu size={14} />
                <span><strong>GhostMeta Solution:</strong> Unicode sanitizer purges all hidden tracking bytes, while the multi-style Humanizer breaks formulaic cadence and replaces AI clichés with authentic human vocabulary.</span>
              </div>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn-primary" onClick={onClose} id="btn-modal-got-it">
            Got it, Let's Clean Content
          </button>
        </div>
      </div>
    </div>
  );
}
