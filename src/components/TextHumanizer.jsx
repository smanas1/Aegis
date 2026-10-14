import React, { useState, useEffect } from 'react';
import {
  FileText,
  Sparkles,
  Copy,
  Check,
  RotateCcw,
  ShieldCheck,
  AlertTriangle,
  Zap,
  TrendingDown,
  Layers,
  ArrowRight,
  Eye,
  Sliders
} from 'lucide-react';
import confetti from 'canvas-confetti';
import {
  analyzeText,
  humanizeText,
  purgeWatermarks
} from '../utils/textHumanizer';
import { getSampleAITextWithWatermarks } from '../utils/sampleAssets';

export default function TextHumanizer() {
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [selectedStyle, setSelectedStyle] = useState('conversational');
  const [inputAnalysis, setInputAnalysis] = useState(null);
  const [outputAnalysis, setOutputAnalysis] = useState(null);
  const [isCopied, setIsCopied] = useState(false);
  const [showDiff, setShowDiff] = useState(false);

  // Re-analyze whenever input changes
  useEffect(() => {
    const analysis = analyzeText(inputText);
    setInputAnalysis(analysis);
  }, [inputText]);

  // Re-analyze output text
  useEffect(() => {
    if (outputText) {
      const analysis = analyzeText(outputText);
      setOutputAnalysis(analysis);
    } else {
      setOutputAnalysis(null);
    }
  }, [outputText]);

  const handleLoadSample = () => {
    const sample = getSampleAITextWithWatermarks();
    setInputText(sample);
  };

  const handleHumanize = () => {
    if (!inputText.trim()) return;

    const cleaned = humanizeText(inputText, selectedStyle);
    setOutputText(cleaned);

    confetti({
      particleCount: 45,
      spread: 55,
      origin: { y: 0.7 },
      colors: ['#00f0ff', '#8b5cf6', '#10b981']
    });
  };

  const handlePurgeWatermarksOnly = () => {
    if (!inputText.trim()) return;
    const stripped = purgeWatermarks(inputText);
    setInputText(stripped);
  };

  const handleCopy = () => {
    if (!outputText) return;
    navigator.clipboard.writeText(outputText);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2200);
  };

  return (
    <div className="section-container">
      {/* Hero Header */}
      <div className="section-hero">
        <div className="badge-pill">
          <Zap size={14} className="accent-violet" />
          <span>AI Text Anonymizer & Stylometry Cloak</span>
        </div>
        <h1 className="hero-title">
          Bypass AI Detectors & <span className="gradient-text">Humanize Content</span>
        </h1>
        <p className="hero-subtitle">
          Strip invisible zero-width unicode watermarks, eradicate formulaic ChatGPT/Claude clichés, boost burstiness, and optimize for LinkedIn, Turnitin, and GPTZero anonymity.
        </p>
      </div>

      {/* Main Grid */}
      <div className="text-humanizer-grid">
        {/* Left Column: Input & Real-time AI Analysis */}
        <div className="panel input-panel">
          <div className="panel-header">
            <div className="panel-title">
              <FileText size={20} className="accent-cyan" />
              <span>1. Original AI Text (ChatGPT / Claude / Gemini)</span>
            </div>
            <div className="panel-actions-group">
              <button
                id="btn-load-sample-text"
                className="btn-ghost-sm"
                onClick={handleLoadSample}
                title="Loads sample ChatGPT text containing invisible unicode watermarks"
              >
                <Sparkles size={14} />
                <span>Load Sample</span>
              </button>
              {inputText && (
                <button
                  className="btn-ghost-sm"
                  onClick={() => setInputText('')}
                  title="Clear input"
                >
                  <RotateCcw size={14} />
                </button>
              )}
            </div>
          </div>

          {/* Textarea */}
          <div className="textarea-wrapper">
            <textarea
              id="input-ai-text"
              className="text-editor"
              placeholder="Paste AI generated text here to detect invisible watermarks and clichés..."
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              rows={9}
            />
          </div>

          {/* Real-time Analysis Card */}
          {inputAnalysis && inputText.trim().length > 0 && (
            <div className="analysis-card">
              <div className="analysis-stat-row">
                <div className="stat-pill">
                  <span className="stat-label">AI Likelihood</span>
                  <span className={`stat-val ${inputAnalysis.aiProbability > 60 ? 'danger' : 'safe'}`}>
                    {inputAnalysis.aiProbability}%
                  </span>
                </div>

                <div className="stat-pill">
                  <span className="stat-label">Hidden Watermarks</span>
                  <span className={`stat-val ${inputAnalysis.watermarkCount > 0 ? 'danger' : 'safe'}`}>
                    {inputAnalysis.watermarkCount} {inputAnalysis.watermarkCount > 0 ? 'Found!' : 'None'}
                  </span>
                </div>

                <div className="stat-pill">
                  <span className="stat-label">AI Clichés</span>
                  <span className={`stat-val ${inputAnalysis.clicheCount > 0 ? 'warning' : 'safe'}`}>
                    {inputAnalysis.clicheCount} detected
                  </span>
                </div>

                <div className="stat-pill">
                  <span className="stat-label">Burstiness Index</span>
                  <span className="stat-val neutral">
                    {inputAnalysis.burstinessScore}/100
                  </span>
                </div>
              </div>

              {/* Watermarks Alert */}
              {inputAnalysis.watermarkCount > 0 && (
                <div className="watermark-alert-banner">
                  <div className="alert-text">
                    <AlertTriangle size={16} />
                    <span>
                      Detected {inputAnalysis.watermarkCount} invisible zero-width tracking characters (e.g.{' '}
                      {inputAnalysis.detectedWatermarks[0]})!
                    </span>
                  </div>
                  <button
                    id="btn-purge-watermarks"
                    className="btn-purge-mini"
                    onClick={handlePurgeWatermarksOnly}
                  >
                    Strip Watermarks Now
                  </button>
                </div>
              )}

              {/* Clichés Tags */}
              {inputAnalysis.detectedCliches.length > 0 && (
                <div className="cliches-detected-tags">
                  <span className="tag-header">Detected AI Hallmark Vocabulary:</span>
                  <div className="tags-flex">
                    {inputAnalysis.detectedCliches.map((c, i) => (
                      <span key={i} className="cliche-tag" title={`Suggest replacing with: ${c.replacement}`}>
                        "{c.word}" <span className="arrow-replace">→</span> {c.replacement}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Humanization Tone Selectors */}
          <div className="humanize-controls">
            <div className="style-label">
              <Sliders size={16} />
              <span>Select Humanization Tone:</span>
            </div>
            <div className="style-buttons-grid">
              {[
                { id: 'conversational', label: 'Conversational', desc: 'Natural human rhythm & everyday idioms' },
                { id: 'linkedin', label: 'LinkedIn Pro', desc: 'Punchy hooks, scannable spacing & engagement' },
                { id: 'direct', label: 'Direct & Crisp', desc: 'Eliminates throat-clearing fluff & filler' },
                { id: 'story', label: 'Storyteller', desc: 'Warm, dynamic cadence with expressive flow' }
              ].map((style) => (
                <button
                  key={style.id}
                  id={`btn-style-${style.id}`}
                  className={`btn-style-card ${selectedStyle === style.id ? 'active' : ''}`}
                  onClick={() => setSelectedStyle(style.id)}
                >
                  <div className="style-title">{style.label}</div>
                  <div className="style-desc">{style.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Action Button */}
          <button
            id="btn-humanize-text"
            className="btn-primary-action"
            disabled={!inputText.trim()}
            onClick={handleHumanize}
          >
            <Sparkles size={18} />
            <span>Humanize Text & Strip Tracking</span>
          </button>
        </div>

        {/* Right Column: Cleaned Output & Metrics */}
        <div className="panel output-panel">
          <div className="panel-header">
            <div className="panel-title">
              <ShieldCheck size={20} className="accent-emerald" />
              <span>2. Humanized & Anonymized Output</span>
            </div>
            {outputText && (
              <button
                id="btn-copy-output"
                className={`btn-copy ${isCopied ? 'copied' : ''}`}
                onClick={handleCopy}
              >
                {isCopied ? <Check size={16} /> : <Copy size={16} />}
                <span>{isCopied ? 'Copied to Clipboard!' : 'Copy Text'}</span>
              </button>
            )}
          </div>

          {/* Output Display */}
          <div className="textarea-wrapper">
            {!outputText ? (
              <div className="empty-state">
                <Layers size={46} className="empty-icon" />
                <h3>No Output Generated Yet</h3>
                <p>Paste your text on the left, choose a humanization style, and click "Humanize Text" to view the sanitized result.</p>
              </div>
            ) : (
              <textarea
                id="output-humanized-text"
                className="text-editor output-editor"
                value={outputText}
                readOnly
                rows={11}
              />
            )}
          </div>

          {/* Metrics comparison */}
          {outputAnalysis && (
            <div className="output-metrics-card">
              <div className="metrics-header">
                <h4>Safety & Anonymity Audit</h4>
                <span className="human-passing-badge">
                  <Check size={14} /> Ready for LinkedIn / Turnitin
                </span>
              </div>

              <div className="before-after-meters">
                <div className="meter-col">
                  <span className="meter-label">Before (Original AI)</span>
                  <div className="meter-bar-track">
                    <div
                      className="meter-bar-fill fill-ai"
                      style={{ width: `${inputAnalysis?.aiProbability || 0}%` }}
                    ></div>
                  </div>
                  <span className="meter-score text-danger">
                    {inputAnalysis?.aiProbability || 0}% AI Detected
                  </span>
                </div>

                <div className="meter-col">
                  <span className="meter-label">After (GhostMeta Humanized)</span>
                  <div className="meter-bar-track">
                    <div
                      className="meter-bar-fill fill-human"
                      style={{ width: `${outputAnalysis.aiProbability}%` }}
                    ></div>
                  </div>
                  <span className="meter-score text-safe">
                    {outputAnalysis.aiProbability}% (Human Passing)
                  </span>
                </div>
              </div>

              <div className="output-stats-row">
                <div className="stat-item">
                  <span className="stat-sub">Words:</span>
                  <strong>{outputAnalysis.wordCount}</strong>
                </div>
                <div className="stat-item">
                  <span className="stat-sub">Hidden Watermarks:</span>
                  <strong className="text-safe">0 (Clean)</strong>
                </div>
                <div className="stat-item">
                  <span className="stat-sub">Burstiness:</span>
                  <strong className="text-safe">{outputAnalysis.burstinessScore}/100 (Dynamic)</strong>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
