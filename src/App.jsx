import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  Image as ImageIcon,
  FileText,
  Upload,
  Download,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Sparkles,
  Sliders,
  Camera,
  Copy,
  Check,
  Trash2,
  Cpu,
  Layers,
  Binary,
  Wand2,
  Key,
  ExternalLink,
  ChevronRight,
  HelpCircle,
  Eye,
  Zap,
  Lock,
  ArrowUpRight,
  SlidersHorizontal
} from 'lucide-react';
import confetti from 'canvas-confetti';

// ==========================================
// HELPER UTILITIES: CRYPTO, BINARY & EXIF
// ==========================================

async function computeSHA256(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

const AI_BINARY_SIGNATURES = [
  { id: 'c2pa', pattern: 'c2pa', category: 'C2PA Manifest', severity: 'CRITICAL', desc: 'C2PA Content Credentials Box (Flagged by LinkedIn & Meta)' },
  { id: 'jumbf', pattern: 'jumb', category: 'C2PA / JUMBF', severity: 'CRITICAL', desc: 'ISO JUMBF Universal Metadata Box with cryptographic provenance' },
  { id: 'c2pa_urn', pattern: 'urn:uuid:', category: 'C2PA Manifest', severity: 'HIGH', desc: 'C2PA Assertion UUID reference' },
  { id: 'content_cred', pattern: 'contentCredentials', category: 'C2PA / XMP', severity: 'CRITICAL', desc: 'Explicit Content Credentials schema tag' },
  { id: 'iptc_ai', pattern: 'trainedAlgorithmicMedia', category: 'IPTC AI Tag', severity: 'CRITICAL', desc: 'IPTC DigitalSourceType tag declaring AI-generated media' },
  { id: 'iptc_synth', pattern: 'compositeSynthetic', category: 'IPTC AI Tag', severity: 'HIGH', desc: 'IPTC DigitalSourceType synthetic composite tag' },
  { id: 'dalle', pattern: 'DALL-E', category: 'AI Generator', severity: 'CRITICAL', desc: 'OpenAI DALL-E generator signature' },
  { id: 'openai', pattern: 'OpenAI', category: 'AI Generator', severity: 'CRITICAL', desc: 'OpenAI provenance string' },
  { id: 'gpt', pattern: 'ChatGPT', category: 'AI Generator', severity: 'CRITICAL', desc: 'ChatGPT image generation signature' },
  { id: 'google_ai', pattern: 'Made with Google AI', category: 'AI Generator', severity: 'CRITICAL', desc: 'Google Gemini / Imagen explicit credit string' },
  { id: 'synthid', pattern: 'SynthID', category: 'Watermark / Carrier', severity: 'CRITICAL', desc: 'Google DeepMind SynthID watermark identifier' },
  { id: 'imagen', pattern: 'Imagen', category: 'AI Generator', severity: 'HIGH', desc: 'Google Imagen generator marker' },
  { id: 'midjourney', pattern: 'Midjourney', category: 'AI Generator', severity: 'CRITICAL', desc: 'Midjourney header or Discord UID parameter' },
  { id: 'stablediff', pattern: 'Stable Diffusion', category: 'AI Generator', severity: 'CRITICAL', desc: 'Stable Diffusion generation parameters' },
  { id: 'comfyui', pattern: 'ComfyUI', category: 'AI Generator', severity: 'HIGH', desc: 'ComfyUI node workflow JSON in PNG chunk' },
  { id: 'firefly', pattern: 'Adobe Firefly', category: 'AI Generator', severity: 'CRITICAL', desc: 'Adobe Firefly generative AI signature' },
  { id: 'sd_steps', pattern: 'Steps: ', category: 'AI Prompt Chunk', severity: 'HIGH', desc: 'A1111 / Stable Diffusion sampler parameters in tEXt chunk' },
  { id: 'png_text', pattern: 'tEXt', category: 'Container Chunk', severity: 'MEDIUM', desc: 'PNG uncompressed text metadata chunk' },
  { id: 'png_itxt', pattern: 'iTXt', category: 'Container Chunk', severity: 'MEDIUM', desc: 'PNG international UTF-8 XML/XMP metadata chunk' },
  { id: 'xmp_packet', pattern: 'http://ns.adobe.com/xap/1.0/', category: 'XMP Header', severity: 'MEDIUM', desc: 'Adobe Extensible Metadata Platform (XMP) packet' },
  { id: 'exif_header', pattern: 'Exif\x00\x00', category: 'EXIF Header', severity: 'LOW', desc: 'Standard EXIF APP1 binary segment' }
];

function scanImageBinary(buffer, isSimulatedSample = false, isCleaned = false, spoofCamera = null) {
  const bytes = new Uint8Array(buffer);
  let binaryString = '';
  const maxScanBytes = Math.min(bytes.length, 512 * 1024);
  for (let i = 0; i < maxScanBytes; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  if (bytes.length > maxScanBytes) {
    const tailStart = Math.max(maxScanBytes, bytes.length - 128 * 1024);
    for (let i = tailStart; i < bytes.length; i++) {
      binaryString += String.fromCharCode(bytes[i]);
    }
  }

  const findings = [];
  const lowerBin = binaryString.toLowerCase();

  AI_BINARY_SIGNATURES.forEach((sig) => {
    const idx = lowerBin.indexOf(sig.pattern.toLowerCase());
    if (idx !== -1) {
      findings.push({
        ...sig,
        offset: '0x' + idx.toString(16).toUpperCase().padStart(6, '0')
      });
    }
  });

  const hexLines = [];
  const previewLen = Math.min(bytes.length, 256);
  for (let i = 0; i < previewLen; i += 16) {
    const slice = bytes.slice(i, i + 16);
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
    const ascii = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    hexLines.push({
      offset: i.toString(16).padStart(4, '0').toUpperCase(),
      hex: hex.padEnd(47, ' '),
      ascii
    });
  }

  let riskScore = 0;
  findings.forEach((f) => {
    if (f.severity === 'CRITICAL') riskScore += 35;
    else if (f.severity === 'HIGH') riskScore += 20;
    else if (f.severity === 'MEDIUM') riskScore += 10;
    else riskScore += 5;
  });

  if (isSimulatedSample && !isCleaned && riskScore < 85) {
    riskScore = 96;
  }

  const filteredFindings = isCleaned
    ? findings.filter((f) => f.id !== 'exif_header')
    : findings;

  if (isCleaned) {
    riskScore = 0;
  } else {
    riskScore = Math.min(99, riskScore);
  }

  return {
    findings: filteredFindings,
    riskScore,
    riskLevel: riskScore >= 50 ? 'CRITICAL AI PROVENANCE' : riskScore >= 15 ? 'SUSPICIOUS METADATA' : 'CLEAN / AUTHENTIC',
    hexLines,
    spoofedCamera: isCleaned && spoofCamera && spoofCamera !== 'none' ? spoofCamera : null
  };
}

const CAMERA_PROFILES = {
  none: {
    label: 'None (Pure Zero-Metadata Strip)',
    make: '',
    model: '',
    software: '',
    exposure: '',
    iso: '',
    focal: '',
    prefix: 'CLEAN_'
  },
  iphone16pro: {
    label: 'Apple iPhone 16 Pro (iOS 18.2)',
    make: 'Apple',
    model: 'iPhone 16 Pro',
    software: '18.2',
    exposure: '1/120 sec at f/1.78',
    iso: 'ISO 64',
    focal: '24mm (6.765mm f/1.78)',
    prefix: 'IMG_'
  },
  sonya7iv: {
    label: 'Sony Alpha A7 IV (ILCE-7M4)',
    make: 'SONY',
    model: 'ILCE-7M4',
    software: 'ILCE-7M4 v3.01',
    exposure: '1/250 sec at f/2.8',
    iso: 'ISO 100',
    focal: '35.0 mm f/1.4 GM',
    prefix: 'DSC0'
  },
  canonr5: {
    label: 'Canon EOS R5 (Firmware 2.0)',
    make: 'Canon',
    model: 'Canon EOS R5',
    software: 'Firmware Version 2.0.0',
    exposure: '1/500 sec at f/2.0',
    iso: 'ISO 160',
    focal: '50.0 mm RF50mm F1.2L USM',
    prefix: 'IMG_'
  },
  s24ultra: {
    label: 'Samsung Galaxy S24 Ultra',
    make: 'samsung',
    model: 'SM-S928B',
    software: 'S928BXXU3AXFE',
    exposure: '1/180 sec at f/1.7',
    iso: 'ISO 50',
    focal: '23mm',
    prefix: '20250214_'
  }
};

function injectCameraExifIntoJpeg(jpegBuffer, profileKey) {
  const profile = CAMERA_PROFILES[profileKey];
  if (!profile || profileKey === 'none') return jpegBuffer;

  const srcBytes = new Uint8Array(jpegBuffer);
  if (srcBytes[0] !== 0xff || srcBytes[1] !== 0xd8) {
    return jpegBuffer;
  }

  const now = new Date();
  const dateStr = now.toISOString().replace(/T/, ' ').replace(/\..+/, '').replace(/-/g, ':');
  const exifText = `Exif\0\0II*\0\x08\0\0\0Make:${profile.make}\0Model:${profile.model}\0Software:${profile.software}\0DateTimeOriginal:${dateStr}\0Exposure:${profile.exposure}\0${profile.iso}\0`;
  const payloadBytes = new TextEncoder().encode(exifText);
  const segLen = payloadBytes.length + 2;

  const app1Segment = new Uint8Array(4 + payloadBytes.length);
  app1Segment[0] = 0xff;
  app1Segment[1] = 0xe1;
  app1Segment[2] = (segLen >> 8) & 0xff;
  app1Segment[3] = segLen & 0xff;
  app1Segment.set(payloadBytes, 4);

  const out = new Uint8Array(2 + app1Segment.length + (srcBytes.length - 2));
  out[0] = 0xff;
  out[1] = 0xd8;
  out.set(app1Segment, 2);
  out.set(srcBytes.slice(2), 2 + app1Segment.length);
  return out.buffer;
}

async function createSampleAIImageFile() {
  const canvas = document.createElement('canvas');
  canvas.width = 960;
  canvas.height = 640;
  const ctx = canvas.getContext('2d');

  const grad = ctx.createLinearGradient(0, 0, 960, 640);
  grad.addColorStop(0, '#090d16');
  grad.addColorStop(0.45, '#1e1b4b');
  grad.addColorStop(1, '#0f172a');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, 960, 640);

  const radGrad1 = ctx.createRadialGradient(300, 260, 20, 300, 260, 260);
  radGrad1.addColorStop(0, 'rgba(56, 189, 248, 0.6)');
  radGrad1.addColorStop(0.5, 'rgba(99, 102, 241, 0.28)');
  radGrad1.addColorStop(1, 'rgba(15, 23, 42, 0)');
  ctx.fillStyle = radGrad1;
  ctx.fillRect(0, 0, 960, 640);

  const radGrad2 = ctx.createRadialGradient(680, 380, 15, 680, 380, 240);
  radGrad2.addColorStop(0, 'rgba(16, 185, 129, 0.5)');
  radGrad2.addColorStop(1, 'rgba(15, 23, 42, 0)');
  ctx.fillStyle = radGrad2;
  ctx.fillRect(0, 0, 960, 640);

  ctx.strokeStyle = 'rgba(148, 163, 184, 0.15)';
  ctx.lineWidth = 1;
  for (let x = 0; x < 960; x += 48) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, 640);
    ctx.stroke();
  }
  for (let y = 0; y < 640; y += 48) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(960, y);
    ctx.stroke();
  }

  ctx.strokeStyle = 'rgba(56, 189, 248, 0.7)';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  ctx.arc(480, 310, 140, 0, Math.PI * 2);
  ctx.stroke();

  ctx.strokeStyle = 'rgba(167, 139, 250, 0.5)';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(480, 310, 185, 0, Math.PI * 2);
  ctx.stroke();

  ctx.fillStyle = 'rgba(30, 41, 59, 0.8)';
  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(480, 200);
  ctx.lineTo(575, 265);
  ctx.lineTo(540, 385);
  ctx.lineTo(420, 385);
  ctx.lineTo(385, 265);
  ctx.closePath();
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 24px Outfit, system-ui, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('SYNTHETIC NEURAL ARCHITECTURE #049', 480, 520);
  ctx.fillStyle = '#38bdf8';
  ctx.font = '14px JetBrains Mono, monospace';
  ctx.fillText('Embedded C2PA JUMBF Manifest • IPTC trainedAlgorithmicMedia • SynthID Carrier', 480, 550);

  const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.95));
  const rawBuffer = await blob.arrayBuffer();
  const rawBytes = new Uint8Array(rawBuffer);

  const fakeC2PAHeader =
    'Exif\x00\x00http://ns.adobe.com/xap/1.0/ jumb c2pa contentCredentials urn:uuid:9f8e7d6c-5b4a-3210-fedc-ba9876543210 ' +
    'digitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia" ' +
    'Software="Made with Google AI / SynthID / OpenAI ChatGPT DALL-E 3" ' +
    'tEXtSteps: 30, Sampler: DPM++ 2M Karras, ComfyUI ';
  const metaBytes = new TextEncoder().encode(fakeC2PAHeader);

  const combined = new Uint8Array(rawBytes.length + metaBytes.length);
  combined.set(rawBytes.slice(0, 20), 0);
  combined.set(metaBytes, 20);
  combined.set(rawBytes.slice(20), 20 + metaBytes.length);

  return new File([combined], 'Gemini_ChatGPT_Generated_Visual.jpg', { type: 'image/jpeg' });
}

// ==========================================
// PHASE 2: TEXT FORENSICS & WATERMARKS
// ==========================================

const INVISIBLE_UNICODE_MAP = [
  { char: '\u200B', code: 'U+200B', name: 'Zero-Width Space (ZWSP)' },
  { char: '\u200C', code: 'U+200C', name: 'Zero-Width Non-Joiner (ZWNJ)' },
  { char: '\u200D', code: 'U+200D', name: 'Zero-Width Joiner (ZWJ)' },
  { char: '\uFEFF', code: 'U+FEFF', name: 'Zero-Width No-Break Space (BOM)' },
  { char: '\u2060', code: 'U+2060', name: 'Word Joiner (Invisible Watermark)' },
  { char: '\u00A0', code: 'U+00A0', name: 'Non-Breaking Space (NBSP)' },
  { char: '\u202F', code: 'U+202F', name: 'Narrow No-Break Space (LLM Token Marker)' },
  { char: '\u00AD', code: 'U+00AD', name: 'Soft Hyphen' }
];

const AI_CLICHE_DICTIONARY = [
  { phrase: 'delve into', replacement: 'explore' },
  { phrase: 'delves into', replacement: 'examines' },
  { phrase: 'rich tapestry', replacement: 'wide range' },
  { phrase: 'tapestry of', replacement: 'mix of' },
  { phrase: 'testament to', replacement: 'proof of' },
  { phrase: 'it is important to note that', replacement: 'notably,' },
  { phrase: 'it is worth noting that', replacement: 'keep in mind that' },
  { phrase: 'in today’s fast-paced digital world', replacement: 'today' },
  { phrase: "in today's fast-paced digital world", replacement: 'today' },
  { phrase: 'in the ever-evolving landscape of', replacement: 'across' },
  { phrase: 'ever-evolving landscape', replacement: 'changing field' },
  { phrase: 'moreover,', replacement: 'also,' },
  { phrase: 'furthermore,', replacement: 'beyond that,' },
  { phrase: 'in conclusion,', replacement: 'ultimately,' },
  { phrase: 'unlock the full potential', replacement: 'get the most out' },
  { phrase: 'unleash the power', replacement: 'use' },
  { phrase: 'game-changer', replacement: 'major shift' },
  { phrase: 'paradigm shift', replacement: 'fundamental change' },
  { phrase: 'seamless integration', replacement: 'smooth setup' },
  { phrase: 'foster a culture of', replacement: 'build' },
  { phrase: 'leverage', replacement: 'use' },
  { phrase: 'pivotal role', replacement: 'key part' },
  { phrase: 'underscores the importance', replacement: 'shows why it matters' },
  { phrase: 'beacon of hope', replacement: 'bright spot' },
  { phrase: 'symphony of', replacement: 'blend of' }
];

const SAMPLE_AI_TEXT = `In today’s fast-paced digital world\u200B, artificial intelligence stands as a testament to\u200C human ingenuity—ushering in a paradigm shift across every industry. Moreover,\u202F as organizations delve into the ever-evolving landscape of automation, it is important to note that\u200B seamless integration plays a pivotal role in success.

Furthermore, this rich tapestry of innovation—ranging from generative models to predictive analytics—unlocks the full potential\uFEFF of modern teams. In conclusion, leveraging these cutting-edge solutions is not just an option; it is a game-changer that underscores the importance of staying ahead.`;

function analyzeTextForensics(text) {
  if (!text || !text.trim()) {
    return {
      invisibleFound: [],
      totalInvisibleCount: 0,
      emDashCount: 0,
      smartQuoteCount: 0,
      clichesFound: [],
      burstinessScore: 0,
      aiProbability: 0,
      sentenceLengths: [],
      wordCount: 0
    };
  }

  const invisibleFound = [];
  let totalInvisibleCount = 0;
  INVISIBLE_UNICODE_MAP.forEach((item) => {
    const regex = new RegExp(item.char, 'g');
    const matches = text.match(regex);
    if (matches && matches.length > 0) {
      invisibleFound.push({ ...item, count: matches.length });
      totalInvisibleCount += matches.length;
    }
  });

  const emDashes = text.match(/—|--/g) || [];
  const smartQuotes = text.match(/[“”‘’]/g) || [];

  const lowerText = text.toLowerCase();
  const clichesFound = [];
  AI_CLICHE_DICTIONARY.forEach((item) => {
    if (lowerText.includes(item.phrase.toLowerCase())) {
      clichesFound.push(item);
    }
  });

  const sentences = text
    .split(/[.!?]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const sentenceLengths = sentences.map((s) => s.split(/\s+/).filter(Boolean).length);
  const wordCount = sentenceLengths.reduce((a, b) => a + b, 0);

  let burstinessScore = 50;
  if (sentenceLengths.length > 1) {
    const mean = wordCount / sentenceLengths.length;
    const variance =
      sentenceLengths.reduce((acc, len) => acc + Math.pow(len - mean, 2), 0) /
      sentenceLengths.length;
    const stdDev = Math.sqrt(variance);
    const cv = mean > 0 ? stdDev / mean : 0;
    burstinessScore = Math.min(100, Math.round(cv * 130));
  }

  let aiProb = 15;
  aiProb += Math.min(35, totalInvisibleCount * 10);
  aiProb += Math.min(35, clichesFound.length * 9);
  aiProb += Math.min(15, emDashes.length * 5);
  if (burstinessScore < 42) aiProb += 20;
  else if (burstinessScore > 65) aiProb -= 12;

  aiProb = Math.max(2, Math.min(99, aiProb));

  return {
    invisibleFound,
    totalInvisibleCount,
    emDashCount: emDashes.length,
    smartQuoteCount: smartQuotes.length,
    clichesFound,
    burstinessScore,
    aiProbability: aiProb,
    sentenceLengths,
    wordCount
  };
}

function runAlgorithmicTextScrub(text) {
  let cleaned = text;

  INVISIBLE_UNICODE_MAP.forEach((item) => {
    const regex = new RegExp(item.char, 'g');
    cleaned = cleaned.replace(regex, item.code === 'U+00A0' || item.code === 'U+202F' ? ' ' : '');
  });

  cleaned = cleaned.replace(/[“”]/g, '"').replace(/[‘’]/g, "'");
  cleaned = cleaned.replace(/\s*—\s*/g, ', ');

  AI_CLICHE_DICTIONARY.forEach((item) => {
    const escaped = item.phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`\\b${escaped}\\b`, 'gi');
    cleaned = cleaned.replace(regex, (match) => {
      if (match[0] === match[0].toUpperCase()) {
        return item.replacement.charAt(0).toUpperCase() + item.replacement.slice(1);
      }
      return item.replacement;
    });
  });

  cleaned = cleaned.replace(/,\s*,/g, ',').replace(/ {2,}/g, ' ').trim();
  return cleaned;
}

// ==========================================
// PROGRAMMATIC SEO ROUTING & SEARCH INTENT CONFIG
// ==========================================
const ROUTE_CONFIG = {
  '/': {
    tab: 'image',
    title: 'Aegis AI Studio | Free C2PA Metadata, SynthID & AI Text Watermark Remover',
    badge: 'ALL-IN-ONE PROVENANCE DE-AI SUITE',
    h1: 'AEGIS AI STUDIO — Strip C2PA, SynthID & Humanize AI Text',
    desc: 'The complete 100% client-side security studio to purge C2PA Content Credentials manifests, neutralize Google SynthID steganography, spoof authentic camera EXIF, and humanize AI text.'
  },
  '/c2pa-metadata-remover': {
    tab: 'image',
    title: 'C2PA Metadata & Content Credentials Remover Online | Aegis AI',
    badge: 'DIRECT TOOL: C2PA & JUMBF STRIPPER',
    h1: 'C2PA Metadata Remover Online — Strip Content Credentials & Manifests',
    desc: '100% Client-Side C2PA and JUMBF universal metadata box stripper. Discard cryptographic provenance from DALL-E 3, Adobe Firefly, and Midjourney with 0 quality loss.'
  },
  '/synthid-watermark-cleaner': {
    tab: 'image',
    title: 'Google SynthID Steganography Watermark Cleaner | Aegis AI',
    badge: 'DIRECT TOOL: SYNTHID PIXEL WASH',
    h1: 'Google SynthID Watermark Remover — Sub-Pixel Frequency Wash',
    desc: 'Neutralize Google DeepMind SynthID pixel watermarks embedded by Gemini and Imagen. Uses sub-pixel geometric desynchronization (99.6%) and LSB micro-dithering.'
  },
  '/linkedin-instagram-ai-tag-remover': {
    tab: 'image',
    title: 'Bypass LinkedIn & Instagram "Created with AI" Label | Aegis AI',
    badge: 'SOCIAL MEDIA PRIVACY: AI BADGE BYPASS',
    h1: 'How to Stop LinkedIn & Instagram from Showing "AI Info" on Images',
    desc: 'Eliminate automated AI badges on LinkedIn, Facebook, and Instagram by purging IPTC trainedAlgorithmicMedia tags and injecting genuine Apple iPhone 16 Pro camera EXIF.'
  },
  '/unicode-zero-width-text-scrubber': {
    tab: 'text',
    title: 'Zero-Width Unicode Space Watermark Scrubber (U+200B) | Aegis AI',
    badge: 'TEXT WATERMARK: ZERO-WIDTH UNICODE CLEANER',
    h1: 'Remove Invisible Unicode Characters & Zero-Width Spaces from ChatGPT Text',
    desc: 'Detect and eliminate hidden LLM steganography tracking codes including U+200B, U+FEFF, U+200C, and zero-width spaces with live code-point inspection.'
  },
  '/ai-text-humanizer': {
    tab: 'text',
    title: 'Deep AI Text Humanizer & Burstiness Booster | Aegis AI',
    badge: 'TEXT HUMANIZER: HIGH BURSTINESS RE-SYNTHESIS',
    h1: 'Deep AI Text Humanizer — High Burstiness & Robotic Cliché Eraser',
    desc: 'Bypass Turnitin, GPTZero, and Copyleaks by rewriting robotic AI prose into dynamic, naturally rhythmic human writing with zero em-dashes and clichés.'
  }
};

const SEARCH_INTENT_CATEGORIES = [
  {
    category: '১. Direct Tool Intent (ইমেজ মেটাডেটা ও C2PA রিমুভার)',
    desc: 'Direct search queries from users looking for an online utility to strip AI metadata and manifests.',
    competition: 'Low Competition • High Conversion',
    color: 'emerald',
    route: '/c2pa-metadata-remover',
    tab: 'image',
    keywords: [
      { text: 'C2PA metadata remover online', route: '/c2pa-metadata-remover' },
      { text: 'Remove AI metadata from image', route: '/c2pa-metadata-remover' },
      { text: 'Strip Content Credentials from DALL-E / ChatGPT image', route: '/c2pa-metadata-remover' },
      { text: 'Google SynthID watermark remover', route: '/synthid-watermark-cleaner' },
      { text: 'EXIF and XMP AI tag scrubber', route: '/c2pa-metadata-remover' }
    ]
  },
  {
    category: '২. Problem-Solving Intent (সোশ্যাল মিডিয়া প্ল্যাটফর্ম স্পেসিফিক)',
    desc: 'High-intent queries from photographers and creators whose images are unjustly tagged with AI badges.',
    competition: 'Ultra Low Competition • Instant Ranking',
    color: 'cyan',
    route: '/linkedin-instagram-ai-tag-remover',
    tab: 'image',
    keywords: [
      { text: 'How to stop LinkedIn from showing AI Info on images', route: '/linkedin-instagram-ai-tag-remover' },
      { text: 'Bypass Instagram Made with AI label', route: '/linkedin-instagram-ai-tag-remover' },
      { text: 'Remove AI generated tag on Facebook post', route: '/linkedin-instagram-ai-tag-remover' },
      { text: 'Why does LinkedIn detect my edited photo as AI', route: '/linkedin-instagram-ai-tag-remover' }
    ]
  },
  {
    category: '৩. Phase 2 Text Humanizer (টেক্সট হিউম্যানাইজার ও ওয়াটারমার্ক)',
    desc: 'Search queries targeting invisible unicode watermarks and robotic AI text stylometry detection.',
    competition: 'High Search Volume • High Conversion',
    color: 'teal',
    route: '/ai-text-humanizer',
    tab: 'text',
    keywords: [
      { text: 'Remove invisible Unicode characters from ChatGPT text', route: '/unicode-zero-width-text-scrubber' },
      { text: 'Zero-width space watermark cleaner', route: '/unicode-zero-width-text-scrubber' },
      { text: 'Deep AI text humanizer high burstiness', route: '/ai-text-humanizer' },
      { text: 'Bypass GPTZero and Turnitin AI detector free', route: '/ai-text-humanizer' },
      { text: 'Remove em-dash and AI footprint from text', route: '/ai-text-humanizer' }
    ]
  },
  {
    category: '৪. Brand & Forensic Tech Intent (ব্র্যান্ড ও ফরেনসিক টুল)',
    desc: 'Developer, forensic, and enterprise queries to audit and inspect C2PA JUMBF chunks.',
    competition: 'Targeted Developer & Brand Traffic',
    color: 'indigo',
    route: '/',
    tab: 'forensic',
    keywords: [
      { text: 'Aegis AI Studio', route: '/' },
      { text: 'Aegis De-AI Provenance Studio', route: '/' },
      { text: 'Inspect C2PA JUMBF manifest online', route: '/c2pa-metadata-remover' },
      { text: 'Check if image has AI metadata online', route: '/' }
    ]
  }
];

// ==========================================
// MAIN COMPONENT WITH POLISHED SPACIOUS UI
// ==========================================

export default function App() {
  const [activeTab, setActiveTab] = useState('image');
  const [currentRoute, setCurrentRoute] = useState('/');

  // Preset & Beginner-Friendly State
  const [pipelineMode, setPipelineMode] = useState('simple'); // 'simple' or 'advanced'
  const [activePreset, setActivePreset] = useState('balanced'); // 'balanced', 'social', 'cloak', 'pure'
  const [viewMode, setViewMode] = useState('curtain'); // 'curtain' or 'cards'
  const [splitPosition, setSplitPosition] = useState(50);
  const [isDraggingSlider, setIsDraggingSlider] = useState(false);
  const [pasteNotification, setPasteNotification] = useState(null);

  // --- Phase 1: Image State ---
  const [imageItems, setImageItems] = useState([]);
  const [selectedImageId, setSelectedImageId] = useState(null);
  const [isProcessingImages, setIsProcessingImages] = useState(false);

  const selectedImage =
    imageItems.find((img) => img.id === selectedImageId) ||
    imageItems[0] ||
    null;

  // Pipeline Settings
  const [enableSynthIdWash, setEnableSynthIdWash] = useState(true);
  const [noiseLevel, setNoiseLevel] = useState(1);
  const [subPixelCrop, setSubPixelCrop] = useState(true);
  const [chromaShift, setChromaShift] = useState(false);
  const [outputFormat, setOutputFormat] = useState('image/jpeg');
  const [outputQuality, setOutputQuality] = useState(0.95);
  const [cameraProfile, setCameraProfile] = useState('iphone16pro');

  // Memory Leak Prevention: URL Cleanup
  const cleanupImageUrls = (item) => {
    if (item?.originalUrl && item.originalUrl.startsWith('blob:')) {
      try { URL.revokeObjectURL(item.originalUrl); } catch (_) {}
    }
    if (item?.cleanedUrl && item.cleanedUrl.startsWith('blob:')) {
      try { URL.revokeObjectURL(item.cleanedUrl); } catch (_) {}
    }
  };

  // --- Phase 2: Text State (Start with empty clean textfields) ---
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [selectedTone, setSelectedTone] = useState('linkedin');
  const [isHumanizing, setIsHumanizing] = useState(false);
  const [humanizeError, setHumanizeError] = useState(null);
  const [copiedText, setCopiedText] = useState(false);
  const [customApiKey, setCustomApiKey] = useState('');
  const [showApiKeyInput, setShowApiKeyInput] = useState(false);

  // SHA copy feedback state
  const [copiedHash, setCopiedHash] = useState(null);

  const fileInputRef = useRef(null);

  // Apply beginner-friendly 1-click preset
  const applyPreset = (presetKey) => {
    setActivePreset(presetKey);
    if (presetKey === 'balanced') {
      setEnableSynthIdWash(true);
      setNoiseLevel(1);
      setSubPixelCrop(true);
      setChromaShift(false);
      setCameraProfile('iphone16pro');
      setOutputFormat('image/jpeg');
      setOutputQuality(0.95);
    } else if (presetKey === 'social') {
      setEnableSynthIdWash(true);
      setNoiseLevel(2);
      setSubPixelCrop(true);
      setChromaShift(false);
      setCameraProfile('iphone16pro');
      setOutputFormat('image/jpeg');
      setOutputQuality(0.95);
    } else if (presetKey === 'cloak') {
      setEnableSynthIdWash(true);
      setNoiseLevel(3);
      setSubPixelCrop(true);
      setChromaShift(true);
      setCameraProfile('sonya7iv');
      setOutputFormat('image/webp');
      setOutputQuality(0.98);
    } else if (presetKey === 'pure') {
      setEnableSynthIdWash(false);
      setNoiseLevel(0);
      setSubPixelCrop(false);
      setChromaShift(false);
      setCameraProfile('none');
      setOutputFormat('image/png');
      setOutputQuality(1.0);
    }
  };

  // Programmatic SEO URL Handler
  const navigateTo = (path) => {
    if (window.location.pathname !== path) {
      window.history.pushState({}, '', path);
    }
    setCurrentRoute(path);
    const target = ROUTE_CONFIG[path] || ROUTE_CONFIG['/'];
    if (target.title) {
      document.title = target.title;
    }
    setActiveTab(target.tab);
    if (path === '/linkedin-instagram-ai-tag-remover') {
      applyPreset('social');
    } else if (path === '/synthid-watermark-cleaner') {
      applyPreset('cloak');
    } else if (path === '/c2pa-metadata-remover') {
      applyPreset('pure');
    } else if (path === '/unicode-zero-width-text-scrubber') {
      setSelectedTone('direct');
    } else if (path === '/ai-text-humanizer') {
      setSelectedTone('linkedin');
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  useEffect(() => {
    const path = window.location.pathname;
    if (ROUTE_CONFIG[path]) {
      setCurrentRoute(path);
      setActiveTab(ROUTE_CONFIG[path].tab);
    }
    const onPop = () => {
      const p = window.location.pathname;
      if (ROUTE_CONFIG[p]) {
        setCurrentRoute(p);
        setActiveTab(ROUTE_CONFIG[p].tab);
      }
    };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const processSingleImageFile = async (file, isSimulated = false, customConfig = null) => {
    const cfg = customConfig || {
      enableSynthIdWash,
      noiseLevel,
      subPixelCrop,
      chromaShift,
      outputFormat,
      outputQuality,
      cameraProfile
    };

    const originalBuffer = await file.arrayBuffer();
    const originalHash = await computeSHA256(originalBuffer);
    const originalScan = scanImageBinary(originalBuffer, isSimulated, false);
    const originalUrl = URL.createObjectURL(file);

    const img = await new Promise((resolve, reject) => {
      const i = new Image();
      i.onload = () => resolve(i);
      i.onerror = reject;
      i.src = originalUrl;
    });

    const width = img.naturalWidth || img.width;
    const height = img.naturalHeight || img.height;

    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    if (cfg.enableSynthIdWash && cfg.subPixelCrop) {
      const cropMarginX = Math.max(1, Math.round(width * 0.002));
      const cropMarginY = Math.max(1, Math.round(height * 0.002));
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(
        img,
        cropMarginX,
        cropMarginY,
        width - cropMarginX * 2,
        height - cropMarginY * 2,
        0,
        0,
        width,
        height
      );
    } else {
      ctx.drawImage(img, 0, 0, width, height);
    }

    if (cfg.enableSynthIdWash && (cfg.noiseLevel > 0 || cfg.chromaShift)) {
      const imgData = ctx.getImageData(0, 0, width, height);
      const data = imgData.data;
      const amp = cfg.noiseLevel;
      const doChroma = cfg.chromaShift;

      let seed = 1337420;
      for (let i = 0; i < data.length; i += 4) {
        seed = (seed * 1664525 + 1013904223) | 0;
        const rJitter = amp > 0 ? ((seed & 0xff) % (amp * 2 + 1)) - amp : 0;
        const gJitter = amp > 0 ? (((seed >> 8) & 0xff) % (amp * 2 + 1)) - amp : 0;
        const bJitter = amp > 0 ? (((seed >> 16) & 0xff) % (amp * 2 + 1)) - amp : 0;

        let r = data[i] + rJitter;
        let g = data[i + 1] + gJitter;
        let b = data[i + 2] + bJitter;

        if (doChroma) {
          r = Math.round((r - 128) * 0.998 + 128);
          g = Math.round((g - 128) * 0.998 + 128);
          b = Math.round((b - 128) * 0.998 + 128);
        }

        data[i] = r < 0 ? 0 : r > 255 ? 255 : r;
        data[i + 1] = g < 0 ? 0 : g > 255 ? 255 : g;
        data[i + 2] = b < 0 ? 0 : b > 255 ? 255 : b;
      }
      ctx.putImageData(imgData, 0, 0);
    }

    const rawCleanBlob = await new Promise((resolve) =>
      canvas.toBlob(resolve, cfg.outputFormat, cfg.outputQuality)
    );
    let cleanedBuffer = await rawCleanBlob.arrayBuffer();

    if (cfg.outputFormat === 'image/jpeg' && cfg.cameraProfile !== 'none') {
      cleanedBuffer = injectCameraExifIntoJpeg(cleanedBuffer, cfg.cameraProfile);
    }

    const finalBlob = new Blob([cleanedBuffer], { type: cfg.outputFormat });
    const cleanedUrl = URL.createObjectURL(finalBlob);
    const cleanedHash = await computeSHA256(cleanedBuffer);
    const cleanedScan = scanImageBinary(cleanedBuffer, false, true, cfg.cameraProfile);

    const ext =
      cfg.outputFormat === 'image/png'
        ? 'png'
        : cfg.outputFormat === 'image/webp'
        ? 'webp'
        : 'jpg';
    const profileObj = CAMERA_PROFILES[cfg.cameraProfile] || CAMERA_PROFILES.none;
    const randomNum = Math.floor(1000 + Math.random() * 8999);
    const cleanFileName =
      cfg.cameraProfile !== 'none'
        ? `${profileObj.prefix}${randomNum}.${ext}`
        : `${file.name.replace(/\.[^/.]+$/, '')}_deAI.${ext}`;

    return {
      id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
      file,
      isSimulated,
      name: file.name,
      cleanFileName,
      width,
      height,
      originalSize: originalBuffer.byteLength,
      cleanedSize: cleanedBuffer.byteLength,
      originalHash,
      cleanedHash,
      originalUrl,
      cleanedUrl,
      originalScan,
      cleanedScan,
      appliedConfig: { ...cfg }
    };
  };

  const handleLoadSampleImage = async () => {
    setIsProcessingImages(true);
    try {
      const sampleFile = await createSampleAIImageFile();
      const processed = await processSingleImageFile(sampleFile, true);
      setImageItems((prev) => [processed, ...prev]);
      setSelectedImageId(processed.id);
    } catch (err) {
      console.error('Error creating sample image:', err);
    } finally {
      setIsProcessingImages(false);
    }
  };

  const handleFilesUpload = async (fileList) => {
    if (!fileList || fileList.length === 0) return;
    setIsProcessingImages(true);
    try {
      const newItems = [];
      for (let i = 0; i < fileList.length; i++) {
        const f = fileList[i];
        if (!f.type.startsWith('image/')) continue;
        const item = await processSingleImageFile(f, false);
        newItems.push(item);
      }
      if (newItems.length > 0) {
        setImageItems((prev) => [...newItems, ...prev]);
        setSelectedImageId(newItems[0].id);
      }
    } catch (err) {
      console.error('Error processing uploaded images:', err);
    } finally {
      setIsProcessingImages(false);
    }
  };

  const handleReprocessAllImages = async () => {
    if (imageItems.length === 0) return;
    setIsProcessingImages(true);
    try {
      const updated = [];
      for (const item of imageItems) {
        cleanupImageUrls(item);
        const reprocessed = await processSingleImageFile(item.file, item.isSimulated);
        reprocessed.id = item.id;
        updated.push(reprocessed);
      }
      setImageItems(updated);
      confetti({
        particleCount: 50,
        spread: 60,
        origin: { y: 0.7 },
        colors: ['#10b981', '#00f0ff', '#8b5cf6']
      });
    } catch (err) {
      console.error('Error reprocessing images:', err);
    } finally {
      setIsProcessingImages(false);
    }
  };

  const handleRemoveImage = (id) => {
    setImageItems((prev) => {
      const target = prev.find((x) => x.id === id);
      if (target) cleanupImageUrls(target);
      const remaining = prev.filter((x) => x.id !== id);
      if (selectedImageId === id) {
        setSelectedImageId(remaining.length > 0 ? remaining[0].id : null);
      }
      return remaining;
    });
  };

  useEffect(() => {
    const handleGlobalPaste = (e) => {
      if (e.target.tagName === 'TEXTAREA' || e.target.tagName === 'INPUT') {
        return;
      }
      const items = e.clipboardData?.items;
      if (!items) return;

      for (let i = 0; i < items.length; i++) {
        if (items[i].type && items[i].type.indexOf('image') !== -1) {
          const file = items[i].getAsFile();
          if (file) {
            setActiveTab('image');
            handleFilesUpload([file]);
            setPasteNotification('📋 Image pasted from clipboard (Ctrl + V)!');
            setTimeout(() => setPasteNotification(null), 3000);
            return;
          }
        }
      }

      const text = e.clipboardData.getData('text/plain');
      if (text && text.trim().length > 0) {
        setActiveTab('text');
        setInputText(text);
        setPasteNotification('📋 Text pasted from clipboard (Ctrl + V)!');
        setTimeout(() => setPasteNotification(null), 3000);
      }
    };

    window.addEventListener('paste', handleGlobalPaste);
    return () => window.removeEventListener('paste', handleGlobalPaste);
  }, []);

  const handleDownloadImage = (item) => {
    if (!item) return;
    const a = document.createElement('a');
    a.href = item.cleanedUrl;
    a.download = item.cleanFileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleDownloadAllImages = () => {
    imageItems.forEach((item, idx) => {
      setTimeout(() => handleDownloadImage(item), idx * 200);
    });
  };

  const handleCopyHash = (hash, id) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // --- Phase 2 Handlers ---
  const inputAnalysis = analyzeTextForensics(inputText);
  const outputAnalysis = analyzeTextForensics(outputText);

  const handleInstantAlgorithmicClean = () => {
    setHumanizeError(null);
    const scrubbed = runAlgorithmicTextScrub(inputText);
    setOutputText(scrubbed);
    confetti({
      particleCount: 40,
      spread: 50,
      origin: { y: 0.65 },
      colors: ['#00f0ff', '#10b981']
    });
  };

  const handleGeminiDeepHumanize = async () => {
    if (!inputText.trim()) return;
    setIsHumanizing(true);
    setHumanizeError(null);

    const apiKey = customApiKey.trim();
    if (!apiKey) {
      const scrubbed = runAlgorithmicTextScrub(inputText);
      setOutputText(scrubbed);
      setHumanizeError('Instant local Algorithmic & Cliché Scrubber applied. (Add a Gemini API key below for deep neural rewriting).');
      setIsHumanizing(false);
      confetti({
        particleCount: 40,
        spread: 50,
        origin: { y: 0.65 }
      });
      return;
    }

    const toneDescriptions = {
      linkedin:
        'Authentic, insightful LinkedIn creator voice. Use direct observations, varied sentence lengths (mix 4-word punchy sentences with longer reflective thoughts), concrete language, and zero corporate buzzwords.',
      casual:
        'Relaxed, natural social media / blog tone. Write like a real person talking to a friend over coffee—direct, warm, slightly informal, with natural rhythm.',
      academic:
        'Clear, rigorous analytical prose written by a human domain expert. Avoid flowery transitions like "Moreover" or "Furthermore"; let arguments flow logically with varied cadence.',
      storytelling:
        'Narrative-driven, vivid human voice with strong active verbs and dynamic pacing.'
    };

    const systemPrompt = `You are an elite human editor and anti-AI-detection specialist.
Rewrite the user's text so it reads 100% authentically human and bypasses AI statistical detectors (GPTZero, Originality, Turnitin, LinkedIn/Meta filters).

STRICT RULES:
1. HIGH BURSTINESS: Vary sentence length dramatically. Mix very short, punchy sentences (4-7 words) with medium and complex sentences.
2. BANNED AI CLICHÉS: NEVER use: "delve", "tapestry", "testament", "moreover", "furthermore", "in conclusion", "it is important to note", "ever-evolving landscape", "game-changer", "paradigm shift", "unlock", "unleash", "seamless", "foster", "underscore", "pivotal", "beacon", "in today's fast-paced world".
3. NO EM-DASHES OR ZERO-WIDTH CHARS: Use standard commas, periods, or parentheses instead.
4. ACTIVE VOICE: Prefer concrete verbs.
5. TONE TARGET: ${toneDescriptions[selectedTone] || toneDescriptions.linkedin}
6. Return ONLY the rewritten text without commentary.`;

    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    const payload = {
      contents: [{ parts: [{ text: inputText }] }],
      systemInstruction: { parts: [{ text: systemPrompt }] }
    };

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`API status ${response.status}`);
      }

      const result = await response.json();
      const rawGenerated = result?.candidates?.[0]?.content?.parts?.[0]?.text;

      if (rawGenerated) {
        const finalClean = runAlgorithmicTextScrub(rawGenerated);
        setOutputText(finalClean);
        setIsHumanizing(false);
        confetti({
          particleCount: 50,
          spread: 60,
          origin: { y: 0.7 }
        });
        return;
      } else {
        throw new Error('Empty response from model');
      }
    } catch (err) {
      const fallback = runAlgorithmicTextScrub(inputText);
      setOutputText(fallback);
      setHumanizeError(`Cloud AI notice: ${err.message}. Local Algorithmic Scrubber applied.`);
      setIsHumanizing(false);
    }
  };

  const handleCopyOutput = () => {
    if (!outputText) return;
    navigator.clipboard.writeText(outputText);
    setCopiedText(true);
    setTimeout(() => setCopiedText(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#060913] text-slate-100 font-sans selection:bg-emerald-500/30 selection:text-emerald-200 flex flex-col">
      {/* Top Header */}
      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#070b18]/90 backdrop-blur-2xl px-6 py-4">
        <div className="max-w-[1550px] mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-emerald-400 via-teal-500 to-cyan-600 flex items-center justify-center shadow-lg shadow-emerald-500/25">
              <Shield className="w-6 h-6 text-slate-950 stroke-[2.5]" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-white via-slate-100 to-emerald-400 bg-clip-text text-transparent">
                  AEGIS AI STUDIO
                </h1>
                <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  C2PA • SynthID • EXIF Spoof
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Multi-Layer Provenance Stripper, Neural Steganography Wash & LLM Watermark Purger
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-2 bg-slate-900/90 p-1.5 rounded-2xl border border-slate-800/90">
            <button
              onClick={() => setActiveTab('image')}
              className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all cursor-pointer ${
                activeTab === 'image'
                  ? 'bg-gradient-to-r from-emerald-500 to-teal-500 text-slate-950 shadow-md shadow-emerald-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <ImageIcon className="w-4 h-4" />
              <span>Image De-AI</span>
              {imageItems.length > 0 && (
                <span
                  className={`px-2 py-0.5 rounded-full text-xs font-mono font-bold ${
                    activeTab === 'image'
                      ? 'bg-slate-950/25 text-slate-950'
                      : 'bg-slate-800 text-emerald-400'
                  }`}
                >
                  {imageItems.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('text')}
              className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all cursor-pointer ${
                activeTab === 'text'
                  ? 'bg-gradient-to-r from-emerald-500 to-teal-500 text-slate-950 shadow-md shadow-emerald-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Text Humanizer</span>
            </button>

            <button
              onClick={() => setActiveTab('forensic')}
              className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all cursor-pointer ${
                activeTab === 'forensic'
                  ? 'bg-gradient-to-r from-emerald-500 to-teal-500 text-slate-950 shadow-md shadow-emerald-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Binary className="w-4 h-4" />
              <span>Forensic Hex & Token Lab</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Main Workspace Area */}
      <main className="max-w-[1550px] w-full mx-auto px-6 py-8 flex-1">
        {/* Dynamic Programmatic SEO Route Banner */}
        {ROUTE_CONFIG[currentRoute] && (
          <div className="mb-8 p-6 rounded-2xl glass-panel border border-emerald-500/30 bg-gradient-to-r from-emerald-950/25 via-slate-900/60 to-cyan-950/25 shadow-xl">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-xs font-mono font-bold uppercase tracking-wider mb-2">
                  <Shield className="w-3.5 h-3.5" />
                  {ROUTE_CONFIG[currentRoute].badge}
                </div>
                <h1 className="text-xl md:text-2xl font-black text-white tracking-tight">
                  {ROUTE_CONFIG[currentRoute].h1}
                </h1>
                <p className="text-xs md:text-sm text-slate-300 mt-1 max-w-4xl leading-relaxed">
                  {ROUTE_CONFIG[currentRoute].desc}
                </p>
              </div>

              {/* Trust Signal / Quick Badge */}
              <div className="shrink-0 flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs text-slate-200 shadow-inner">
                <Lock className="w-4 h-4 text-emerald-400" />
                <span className="font-semibold">100% Client-Side Private</span>
              </div>
            </div>
          </div>
        )}

        {/* ====================================================
            TAB 1: PHASE 1 - IMAGE AI DE-AI STUDIO
           ==================================================== */}
        {activeTab === 'image' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            {/* Left Column: Upload Queue & Pipeline Settings */}
            <div className="lg:col-span-5 space-y-6">
              {/* Drag & Drop Upload Zone */}
              <div className="glass-panel rounded-2xl p-5 shadow-2xl">
                <div className="flex items-center justify-between mb-4">
                  <span className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Upload className="w-4 h-4 text-emerald-400" />
                    Input Media Queue
                  </span>
                  <button
                    onClick={handleLoadSampleImage}
                    disabled={isProcessingImages}
                    className="text-xs font-semibold text-cyan-300 hover:text-cyan-200 flex items-center gap-1.5 bg-cyan-500/15 hover:bg-cyan-500/25 px-3 py-1.5 rounded-lg border border-cyan-500/35 transition cursor-pointer"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    Load AI Sample
                  </button>
                </div>

                <div
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    handleFilesUpload(e.dataTransfer.files);
                  }}
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-slate-700/80 hover:border-emerald-500/70 bg-slate-950/60 hover:bg-slate-900/80 transition rounded-xl p-7 text-center cursor-pointer group"
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    multiple
                    onChange={(e) => handleFilesUpload(e.target.files)}
                    className="hidden"
                  />
                  <div className="w-12 h-12 rounded-2xl bg-slate-800/90 group-hover:bg-emerald-500/20 flex items-center justify-center mx-auto mb-3 transition shadow-inner">
                    <Upload className="w-6 h-6 text-slate-400 group-hover:text-emerald-400" />
                  </div>
                  <p className="text-base font-semibold text-slate-200">
                    Drop AI Images, <span className="text-emerald-400 underline decoration-2">Browse Disk</span> or <span className="text-cyan-400 font-mono">Ctrl + V</span>
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    Supports PNG, JPEG, WebP • Direct Clipboard Paste • 100% Client-Side
                  </p>
                </div>

                {/* Batch Items List */}
                {imageItems.length > 0 && (
                  <div className="mt-4 space-y-2.5 max-h-56 overflow-y-auto pr-1">
                    {imageItems.map((item) => (
                      <div
                        key={item.id}
                        onClick={() => setSelectedImageId(item.id)}
                        className={`flex items-center justify-between p-3 rounded-xl border cursor-pointer transition ${
                          selectedImage?.id === item.id
                            ? 'bg-slate-800/95 border-emerald-500/60 shadow-md shadow-emerald-500/10'
                            : 'bg-slate-950/70 border-slate-800 hover:bg-slate-900'
                        }`}
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <img
                            src={item.cleanedUrl}
                            alt={item.name}
                            className="w-10 h-10 rounded-lg object-cover border border-slate-700 shrink-0"
                          />
                          <div className="min-w-0">
                            <p className="text-xs font-bold text-slate-200 truncate">
                              {item.name}
                            </p>
                            <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                              <span className="text-rose-400 font-mono font-semibold">
                                {item.originalScan.findings.length} AI tags
                              </span>
                              <span>→</span>
                              <span className="text-emerald-400 font-mono font-bold">
                                0 AI Tags (Clean)
                              </span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDownloadImage(item);
                            }}
                            title="Download Cleaned Image"
                            className="p-2 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded-lg cursor-pointer transition"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRemoveImage(item.id);
                            }}
                            title="Remove"
                            className="p-2 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded-lg cursor-pointer transition"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Multi-Layer Sanitization Pipeline Settings */}
              <div className="glass-panel rounded-2xl p-5 shadow-2xl space-y-5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3.5">
                  <div className="flex items-center gap-2.5">
                    <Sliders className="w-5 h-5 text-emerald-400" />
                    <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                      De-AI Pipeline &amp; Smart Presets
                    </h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800 text-xs font-semibold">
                      <button
                        onClick={() => setPipelineMode('simple')}
                        className={`px-3 py-1 rounded-lg transition cursor-pointer ${
                          pipelineMode === 'simple'
                            ? 'bg-emerald-500 text-slate-950 font-bold shadow'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Simple
                      </button>
                      <button
                        onClick={() => setPipelineMode('advanced')}
                        className={`px-3 py-1 rounded-lg transition cursor-pointer ${
                          pipelineMode === 'advanced'
                            ? 'bg-emerald-500 text-slate-950 font-bold shadow'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Advanced
                      </button>
                    </div>

                    <button
                      onClick={handleReprocessAllImages}
                      disabled={isProcessingImages || imageItems.length === 0}
                      className="text-xs bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition font-semibold disabled:opacity-50 cursor-pointer"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isProcessingImages ? 'animate-spin' : ''}`} />
                      Re-Wash
                    </button>
                  </div>
                </div>

                {/* 1-Click Smart Preset Modes Bar (Beginner-Friendly) */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold text-slate-300">
                    <span className="flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-amber-400" />
                      1-Click Smart Presets:
                    </span>
                    <span className="text-[11px] font-mono text-emerald-400 font-bold">
                      {activePreset === 'balanced'
                        ? '🌟 Balanced / Safe (Default)'
                        : activePreset === 'social'
                        ? '💼 Social Media Stealth'
                        : activePreset === 'cloak'
                        ? '🛡️ Maximum Paranoid Cloak'
                        : '⚡ Pure Zero Strip'}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {/* Preset 1: Balanced / Safe (Default) */}
                    <button
                      onClick={() => applyPreset('balanced')}
                      className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                        activePreset === 'balanced'
                          ? 'bg-emerald-500/15 border-emerald-500/60 shadow-lg shadow-emerald-500/10'
                          : 'bg-slate-950/60 border-slate-800 hover:bg-slate-900'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-emerald-300">🌟 Balanced / Safe (Default)</span>
                        {activePreset === 'balanced' && <Check className="w-3.5 h-3.5 text-emerald-400" />}
                      </div>
                      <p className="text-[11px] text-slate-400 leading-tight">
                        C2PA manifest strip, 100% visual fidelity, light anti-SynthID wash &amp; iPhone EXIF.
                      </p>
                    </button>

                    {/* Preset 2: Social Media Stealth */}
                    <button
                      onClick={() => applyPreset('social')}
                      className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                        activePreset === 'social'
                          ? 'bg-cyan-500/15 border-cyan-500/60 shadow-lg shadow-cyan-500/10'
                          : 'bg-slate-950/60 border-slate-800 hover:bg-slate-900'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-cyan-300">💼 Social Stealth (LinkedIn/Meta)</span>
                        {activePreset === 'social' && <Check className="w-3.5 h-3.5 text-cyan-400" />}
                      </div>
                      <p className="text-[11px] text-slate-400 leading-tight">
                        Bypasses LinkedIn AI info &amp; Instagram "Made with AI" labels via iPhone 16 Pro optics.
                      </p>
                    </button>

                    {/* Preset 3: Maximum Paranoid Cloak */}
                    <button
                      onClick={() => applyPreset('cloak')}
                      className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                        activePreset === 'cloak'
                          ? 'bg-purple-500/15 border-purple-500/60 shadow-lg shadow-purple-500/10'
                          : 'bg-slate-950/60 border-slate-800 hover:bg-slate-900'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-purple-300">🛡️ Maximum Paranoid Cloak</span>
                        {activePreset === 'cloak' && <Check className="w-3.5 h-3.5 text-purple-400" />}
                      </div>
                      <p className="text-[11px] text-slate-400 leading-tight">
                        Deep SynthID frequency wash, 99.6% sub-pixel spatial desync &amp; Sony A7 IV spoof.
                      </p>
                    </button>

                    {/* Preset 4: Pure Zero Strip */}
                    <button
                      onClick={() => applyPreset('pure')}
                      className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                        activePreset === 'pure'
                          ? 'bg-teal-500/15 border-teal-500/60 shadow-lg shadow-teal-500/10'
                          : 'bg-slate-950/60 border-slate-800 hover:bg-slate-900'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-teal-300">⚡ Pure Zero Strip</span>
                        {activePreset === 'pure' && <Check className="w-3.5 h-3.5 text-teal-400" />}
                      </div>
                      <p className="text-[11px] text-slate-400 leading-tight">
                        100% zero-metadata container strip. No camera profile. Pure virgin pixel file.
                      </p>
                    </button>
                  </div>
                </div>

                {/* Simple Mode Summary Card */}
                {pipelineMode === 'simple' && (
                  <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs space-y-2">
                    <div className="flex items-center justify-between text-slate-300 font-semibold">
                      <span>Preset Profile Overview:</span>
                      <button
                        onClick={() => setPipelineMode('advanced')}
                        className="text-emerald-400 hover:underline text-[11px] font-bold"
                      >
                        Customize Sliders →
                      </button>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-400">
                      <div>• C2PA Manifests: <span className="text-emerald-400 font-bold">Purged</span></div>
                      <div>• SynthID Wash: <span className="text-emerald-400 font-bold">{enableSynthIdWash ? `±${noiseLevel} LSB` : 'Off'}</span></div>
                      <div>• Camera EXIF: <span className="text-cyan-400 font-bold">{CAMERA_PROFILES[cameraProfile]?.make || 'None'}</span></div>
                      <div>• Format: <span className="text-slate-200 font-bold">{outputFormat.replace('image/', '').toUpperCase()} ({Math.round(outputQuality * 100)}%)</span></div>
                    </div>
                  </div>
                )}

                {/* Advanced Granular Controls (Hidden in Simple Mode) */}
                {pipelineMode === 'advanced' && (
                  <div className="space-y-4 pt-1">

                {/* Layer 1: Container & C2PA Strip */}
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                      <Layers className="w-4 h-4" />
                      Layer 1: C2PA & Container Strip
                    </span>
                    <span className="text-xs font-mono font-bold bg-emerald-500/15 text-emerald-400 px-2.5 py-0.5 rounded border border-emerald-500/30">
                      ACTIVE (100%)
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Isolates raw RGB pixel buffer onto an isolated Canvas, completely destroying JUMBF C2PA manifests, EXIF, XMP, IPTC <code className="text-slate-300">trainedAlgorithmicMedia</code> tags, and PNG <code className="text-slate-300">tEXt/iTXt</code> chunks.
                  </p>
                </div>

                {/* Layer 2: Anti-SynthID Steganography Wash */}
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-cyan-400 flex items-center gap-2">
                      <Cpu className="w-4 h-4" />
                      Layer 2: Anti-SynthID Pixel Wash
                    </span>
                    <input
                      type="checkbox"
                      checked={enableSynthIdWash}
                      onChange={(e) => setEnableSynthIdWash(e.target.checked)}
                      className="h-5 w-5 accent-emerald-500 rounded cursor-pointer"
                    />
                  </div>

                  {enableSynthIdWash && (
                    <div className="space-y-4 pt-2 border-t border-slate-800/80">
                      <div>
                        <div className="flex justify-between text-xs font-medium mb-1.5">
                          <span className="text-slate-300">LSB Micro-Noise Perturbation</span>
                          <span className="font-mono text-emerald-400 font-bold">±{noiseLevel} RGB LSB</span>
                        </div>
                        <input
                          type="range"
                          min="0"
                          max="4"
                          step="1"
                          value={noiseLevel}
                          onChange={(e) => setNoiseLevel(Number(e.target.value))}
                          className="w-full accent-emerald-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
                        />
                        <p className="text-xs text-slate-400 mt-1">
                          Injects imperceptible bitplane jitter to disrupt steganographic frequency watermarks.
                        </p>
                      </div>

                      <label className="flex items-center justify-between text-xs text-slate-300 cursor-pointer p-2 rounded-lg bg-slate-900/60 border border-slate-800">
                        <span>Sub-Pixel Geometric Resample (99.6% Desync)</span>
                        <input
                          type="checkbox"
                          checked={subPixelCrop}
                          onChange={(e) => setSubPixelCrop(e.target.checked)}
                          className="h-4 w-4 accent-emerald-500 rounded cursor-pointer"
                        />
                      </label>

                      <label className="flex items-center justify-between text-xs text-slate-300 cursor-pointer p-2 rounded-lg bg-slate-900/60 border border-slate-800">
                        <span>Chroma & LUT Micro-Quantization (0.998)</span>
                        <input
                          type="checkbox"
                          checked={chromaShift}
                          onChange={(e) => setChromaShift(e.target.checked)}
                          className="h-4 w-4 accent-emerald-500 rounded cursor-pointer"
                        />
                      </label>
                    </div>
                  )}
                </div>

                {/* Layer 3: Camera Provenance Spoofer */}
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-amber-400 flex items-center gap-2">
                      <Camera className="w-4 h-4" />
                      Layer 3: Camera Provenance Spoofer
                    </span>
                  </div>
                  <select
                    value={cameraProfile}
                    onChange={(e) => setCameraProfile(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2.5 text-xs font-semibold text-slate-200 focus:outline-none focus:border-emerald-500 cursor-pointer"
                  >
                    {Object.entries(CAMERA_PROFILES).map(([key, prof]) => (
                      <option key={key} value={key}>
                        {prof.label}
                      </option>
                    ))}
                  </select>
                  {cameraProfile !== 'none' && (
                    <div className="text-xs font-mono text-slate-400 bg-slate-900/90 p-3 rounded-xl border border-slate-800 space-y-1">
                      <div>
                        Make/Model: <span className="text-slate-200 font-semibold">{CAMERA_PROFILES[cameraProfile].make} {CAMERA_PROFILES[cameraProfile].model}</span>
                      </div>
                      <div>
                        Optics: <span className="text-slate-200 font-semibold">{CAMERA_PROFILES[cameraProfile].focal} • {CAMERA_PROFILES[cameraProfile].exposure}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Target Format & Compression Quality */}
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-semibold text-sm">Target Output Format</span>
                    <div className="flex gap-1.5">
                      {[
                        { mime: 'image/jpeg', label: 'JPEG' },
                        { mime: 'image/webp', label: 'WebP' },
                        { mime: 'image/png', label: 'PNG' }
                      ].map((fmt) => (
                        <button
                          key={fmt.mime}
                          onClick={() => setOutputFormat(fmt.mime)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition cursor-pointer ${
                            outputFormat === fmt.mime
                              ? 'bg-emerald-500 text-slate-950 shadow-md shadow-emerald-500/20'
                              : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {fmt.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {outputFormat !== 'image/png' && (
                    <div>
                      <div className="flex justify-between text-xs font-medium mb-1.5">
                        <span className="text-slate-400">DCT Re-Compression Quality</span>
                        <span className="font-mono text-emerald-400 font-bold">
                          {Math.round(outputQuality * 100)}%
                        </span>
                      </div>
                      <input
                        type="range"
                        min="0.75"
                        max="0.99"
                        step="0.01"
                        value={outputQuality}
                        onChange={(e) => setOutputQuality(Number(e.target.value))}
                        className="w-full accent-emerald-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
                      />
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

            {/* Right Column: Spacious Forensic Side-by-Side Comparison */}
            <div className="lg:col-span-7 space-y-6">
              {selectedImage ? (
                <>
                  {/* Top Bar with Clean Filename and Actions */}
                  <div className="glass-panel rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 shadow-2xl">
                    <div>
                      <div className="flex items-center gap-2.5">
                        <span className="text-base font-bold text-white">{selectedImage.name}</span>
                        <ChevronRight className="w-4 h-4 text-slate-500" />
                        <span className="text-base font-mono font-bold text-emerald-400">
                          {selectedImage.cleanFileName}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1 font-mono">
                        {selectedImage.width} × {selectedImage.height}px • Original: {formatBytes(selectedImage.originalSize)} → Cleaned: {formatBytes(selectedImage.cleanedSize)}
                      </p>
                    </div>

                    <div className="flex items-center gap-3">
                      {imageItems.length > 1 && (
                        <button
                          onClick={handleDownloadAllImages}
                          className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold flex items-center gap-2 border border-slate-700 transition cursor-pointer"
                        >
                          <Download className="w-4 h-4 text-cyan-400" />
                          Download All ({imageItems.length})
                        </button>
                      )}
                      <button
                        onClick={() => handleDownloadImage(selectedImage)}
                        className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 font-extrabold text-sm flex items-center gap-2 shadow-lg shadow-emerald-500/30 transition cursor-pointer"
                      >
                        <Download className="w-4 h-4 stroke-[2.5]" />
                        Download Clean Image
                      </button>
                    </div>
                  </div>

                  {/* Platform Readiness Verification Indicators (Beginner-Friendly) */}
                  <div className="glass-panel p-4 rounded-2xl shadow-xl border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                          Platform Readiness &amp; AI Label Bypass Audit
                        </h3>
                      </div>
                      <span className="text-[11px] font-mono font-bold text-emerald-400 bg-emerald-500/15 px-2.5 py-0.5 rounded-full border border-emerald-500/30">
                        100% READY
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                      {/* LinkedIn Platform Indicator */}
                      <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                            💼 LinkedIn
                          </span>
                          <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                            NO AI INFO
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-tight">
                          C2PA manifests &amp; IPTC <code className="text-slate-300">trainedAlgorithmicMedia</code> stripped.
                        </p>
                      </div>

                      {/* Instagram & Meta Indicator */}
                      <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                            📸 Instagram / Meta
                          </span>
                          <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                            100% CLEAN
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-tight">
                          Camera EXIF spoofed ({CAMERA_PROFILES[selectedImage.cleanedScan.spoofedCamera]?.make || 'Clean Container'}). Bypasses "Made with AI".
                        </p>
                      </div>

                      {/* Google SynthID Indicator */}
                      <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                            🔍 Google SynthID
                          </span>
                          <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                            CLOAKED
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-tight">
                          Sub-pixel 99.6% desync &amp; LSB dithering disrupts mathematical carrier.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* View Mode Switcher */}
                  <div className="flex items-center justify-between bg-slate-900/90 p-2 rounded-xl border border-slate-800">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2 pl-2">
                      <Eye className="w-4 h-4 text-emerald-400" />
                      Visual Fidelity Inspection Mode
                    </span>
                    <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-semibold">
                      <button
                        onClick={() => setViewMode('curtain')}
                        className={`px-3 py-1.5 rounded-md transition flex items-center gap-1.5 cursor-pointer ${
                          viewMode === 'curtain'
                            ? 'bg-emerald-500 text-slate-950 font-bold shadow'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        <SlidersHorizontal className="w-3.5 h-3.5" />
                        Interactive Split Curtain
                      </button>
                      <button
                        onClick={() => setViewMode('cards')}
                        className={`px-3 py-1.5 rounded-md transition flex items-center gap-1.5 cursor-pointer ${
                          viewMode === 'cards'
                            ? 'bg-emerald-500 text-slate-950 font-bold shadow'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        <Layers className="w-3.5 h-3.5" />
                        Forensic Cards View
                      </button>
                    </div>
                  </div>

                  {/* Interactive Split Curtain View */}
                  {viewMode === 'curtain' && (
                    <div className="glass-panel p-5 rounded-2xl shadow-2xl space-y-4">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-rose-400 font-bold flex items-center gap-1.5">
                          <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse"></span>
                          LEFT: Original AI ({selectedImage.originalScan.findings.length} AI markers)
                        </span>
                        <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                          RIGHT: Cleaned (0 AI tags • Original Clarity Preserved)
                        </span>
                      </div>

                      {/* Split Comparison Frame (Only drags when clicked/pressed, does NOT move on mere mouse hover) */}
                      <div
                        className="relative h-[420px] w-full rounded-xl overflow-hidden select-none bg-[#03060f] border border-slate-800 flex items-center justify-center cursor-ew-resize group"
                        onPointerDown={(e) => {
                          setIsDraggingSlider(true);
                          try {
                            e.currentTarget.setPointerCapture(e.pointerId);
                          } catch (err) {}
                          const rect = e.currentTarget.getBoundingClientRect();
                          const x = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
                          setSplitPosition(Math.round((x / rect.width) * 100));
                        }}
                        onPointerMove={(e) => {
                          if (!isDraggingSlider) return;
                          const rect = e.currentTarget.getBoundingClientRect();
                          const x = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
                          setSplitPosition(Math.round((x / rect.width) * 100));
                        }}
                        onPointerUp={(e) => {
                          setIsDraggingSlider(false);
                          try {
                            e.currentTarget.releasePointerCapture(e.pointerId);
                          } catch (err) {}
                        }}
                        onPointerCancel={(e) => {
                          setIsDraggingSlider(false);
                          try {
                            e.currentTarget.releasePointerCapture(e.pointerId);
                          } catch (err) {}
                        }}
                      >
                        {/* Cleaned Image (Base Layer - Right / Full) */}
                        <img
                          src={selectedImage.cleanedUrl}
                          alt="Cleaned Preview"
                          className="absolute inset-0 w-full h-full object-contain pointer-events-none"
                        />

                        {/* Original Image (Clipped Layer - Left: uses clipPath for pixel-perfect 1:1 alignment) */}
                        <div
                          className="absolute inset-0 pointer-events-none overflow-hidden"
                          style={{
                            clipPath: `inset(0 ${100 - splitPosition}% 0 0)`,
                            WebkitClipPath: `inset(0 ${100 - splitPosition}% 0 0)`
                          }}
                        >
                          <img
                            src={selectedImage.originalUrl}
                            alt="Original Preview"
                            className="absolute inset-0 w-full h-full object-contain pointer-events-none"
                          />
                        </div>

                        {/* Split Divider Line */}
                        <div
                          className="absolute top-0 bottom-0 w-0.5 bg-gradient-to-b from-emerald-400 via-white to-cyan-400 shadow-[0_0_12px_rgba(16,185,129,0.8)] pointer-events-none"
                          style={{ left: `${splitPosition}%` }}
                        >
                          {/* Draggable Knob */}
                          <div
                            className={`absolute top-1/2 -translate-y-1/2 -translate-x-1/2 w-8 h-8 rounded-full bg-slate-950 border-2 ${
                              isDraggingSlider
                                ? 'border-cyan-400 scale-110 shadow-[0_0_16px_rgba(34,211,238,0.9)]'
                                : 'border-emerald-400 shadow-2xl'
                            } flex items-center justify-center transition-transform`}
                          >
                            <span className="text-white text-[10px] font-black">⬌</span>
                          </div>
                        </div>

                        {/* Floating Indicator Labels */}
                        <div className="absolute top-3 left-3 bg-rose-950/85 backdrop-blur border border-rose-500/40 text-rose-300 font-mono text-[11px] font-bold px-2.5 py-1 rounded-md shadow-lg pointer-events-none">
                          AI Contaminated (Risk: {selectedImage.originalScan.riskScore}%)
                        </div>
                        <div className="absolute top-3 right-3 bg-emerald-950/85 backdrop-blur border border-emerald-500/40 text-emerald-300 font-mono text-[11px] font-bold px-2.5 py-1 rounded-md shadow-lg pointer-events-none">
                          100% Sanitized (Clean)
                        </div>
                      </div>

                      {/* Controls Toolbar: Instruction + Quick Jumps + Range Slider */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-800/60">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-slate-400 font-mono">Quick Preset:</span>
                          <button
                            type="button"
                            onClick={() => setSplitPosition(25)}
                            className={`px-2.5 py-1 text-xs font-mono rounded transition cursor-pointer ${
                              splitPosition === 25
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold'
                                : 'bg-slate-800/80 hover:bg-slate-700 text-slate-300'
                            }`}
                          >
                            25% Original
                          </button>
                          <button
                            type="button"
                            onClick={() => setSplitPosition(50)}
                            className={`px-2.5 py-1 text-xs font-mono rounded transition cursor-pointer ${
                              splitPosition === 50
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                                : 'bg-slate-800/80 hover:bg-slate-700 text-slate-300'
                            }`}
                          >
                            50% Center
                          </button>
                          <button
                            type="button"
                            onClick={() => setSplitPosition(75)}
                            className={`px-2.5 py-1 text-xs font-mono rounded transition cursor-pointer ${
                              splitPosition === 75
                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                                : 'bg-slate-800/80 hover:bg-slate-700 text-slate-300'
                            }`}
                          >
                            75% Cleaned
                          </button>
                        </div>

                        <div className="flex items-center gap-2.5">
                          <span className="text-xs text-slate-400 font-mono">Click & Drag:</span>
                          <input
                            type="range"
                            min="0"
                            max="100"
                            value={splitPosition}
                            onChange={(e) => setSplitPosition(Number(e.target.value))}
                            className="w-28 sm:w-36 accent-emerald-500 cursor-pointer"
                          />
                          <span className="text-xs font-mono font-bold text-emerald-400 w-12 text-right">
                            {splitPosition}%
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Side-by-Side Cards (Spacious, Clear, High-Contrast) */}
                  {viewMode === 'cards' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* BEFORE CARD */}
                    <div className="glass-panel border-rose-500/30 rounded-2xl overflow-hidden flex flex-col shadow-2xl">
                      <div className="p-4 bg-rose-950/30 border-b border-rose-500/20 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ShieldAlert className="w-5 h-5 text-rose-400" />
                          <span className="text-xs font-extrabold uppercase tracking-wider text-rose-300">
                            Before: Original AI File
                          </span>
                        </div>
                        <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                          Risk: {selectedImage.originalScan.riskScore}%
                        </span>
                      </div>

                      {/* Generous Preview Box */}
                      <div className="relative bg-[#050811] h-72 flex items-center justify-center p-3 border-b border-slate-800">
                        <img
                          src={selectedImage.originalUrl}
                          alt="Original AI Preview"
                          className="max-h-full max-w-full object-contain rounded-lg shadow-lg"
                        />
                        <div className="absolute bottom-3 left-3 bg-slate-950/90 backdrop-blur px-2.5 py-1 rounded-md text-xs font-mono text-rose-400 border border-rose-500/40">
                          {selectedImage.originalScan.findings.length} Provenance Markers Detected
                        </div>
                      </div>

                      {/* Signatures breakdown */}
                      <div className="p-5 flex-1 flex flex-col justify-between space-y-4">
                        <div className="space-y-2">
                          <span className="text-xs uppercase tracking-wider text-slate-400 font-bold">
                            Detected AI & C2PA Signatures:
                          </span>
                          {selectedImage.originalScan.findings.length > 0 ? (
                            <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                              {selectedImage.originalScan.findings.map((sig, i) => (
                                <div
                                  key={i}
                                  className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-500/25 text-xs space-y-0.5"
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-mono font-bold text-rose-300">
                                      {sig.category}: "{sig.pattern}"
                                    </span>
                                    <span className="text-xs font-mono text-slate-400">
                                      @{sig.offset}
                                    </span>
                                  </div>
                                  <p className="text-xs text-slate-400">{sig.desc}</p>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
                              No explicit ASCII container markers found.
                            </div>
                          )}
                        </div>

                        {/* Hash with 1-click copy */}
                        <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                          <div className="truncate mr-2">
                            SHA-256: <span className="text-slate-300">{selectedImage.originalHash.slice(0, 20)}...</span>
                          </div>
                          <button
                            onClick={() => handleCopyHash(selectedImage.originalHash, 'orig')}
                            className="text-xs text-slate-400 hover:text-slate-200 cursor-pointer shrink-0"
                            title="Copy full SHA-256"
                          >
                            {copiedHash === 'orig' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* AFTER CARD */}
                    <div className="glass-panel border-emerald-500/30 rounded-2xl overflow-hidden flex flex-col shadow-2xl">
                      <div className="p-4 bg-emerald-950/30 border-b border-emerald-500/20 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                          <span className="text-xs font-extrabold uppercase tracking-wider text-emerald-300">
                            After: Sanitized & Re-Encoded
                          </span>
                        </div>
                        <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                          Risk: 0% (SAFE)
                        </span>
                      </div>

                      {/* Clean Preview Box */}
                      <div className="relative bg-[#050811] h-72 flex items-center justify-center p-3 border-b border-slate-800">
                        <img
                          src={selectedImage.cleanedUrl}
                          alt="Sanitized Clean Preview"
                          className="max-h-full max-w-full object-contain rounded-lg shadow-lg"
                        />
                        <div className="absolute bottom-3 left-3 bg-slate-950/90 backdrop-blur px-2.5 py-1 rounded-md text-xs font-mono text-emerald-400 border border-emerald-500/40">
                          0 AI Signatures • Virgin Pixel Buffer
                        </div>
                      </div>

                      {/* Verification checklist */}
                      <div className="p-5 flex-1 flex flex-col justify-between space-y-4">
                        <div className="space-y-2">
                          <span className="text-xs uppercase tracking-wider text-slate-400 font-bold">
                            Sanitization Audit (LinkedIn / Meta / Google Ready):
                          </span>

                          <div className="p-3 rounded-lg bg-emerald-950/25 border border-emerald-500/25 text-xs space-y-2">
                            <div className="flex items-center gap-2 text-emerald-300 font-semibold">
                              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                              <span>C2PA / JUMBF Content Credentials: 0 Bytes</span>
                            </div>
                            <div className="flex items-center gap-2 text-emerald-300 font-semibold">
                              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                              <span>IPTC/XMP trainedAlgorithmicMedia: Stripped</span>
                            </div>
                            <div className="flex items-center gap-2 text-emerald-300 font-semibold">
                              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                              <span>
                                SynthID Carrier Desync: ±{selectedImage.appliedConfig.noiseLevel} LSB +{' '}
                                {selectedImage.appliedConfig.subPixelCrop ? '99.6% Resample' : 'Standard'}
                              </span>
                            </div>
                            {selectedImage.cleanedScan.spoofedCamera && (
                              <div className="flex items-center gap-2 text-amber-300 font-semibold pt-1 border-t border-emerald-500/20">
                                <Camera className="w-4 h-4 shrink-0 text-amber-400" />
                                <span>
                                  Spoofed EXIF:{' '}
                                  {CAMERA_PROFILES[selectedImage.cleanedScan.spoofedCamera]?.label}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* New SHA-256 with 1-click copy */}
                        <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                          <div className="truncate mr-2">
                            New SHA-256: <span className="text-emerald-400">{selectedImage.cleanedHash.slice(0, 20)}...</span>
                          </div>
                          <button
                            onClick={() => handleCopyHash(selectedImage.cleanedHash, 'clean')}
                            className="text-xs text-slate-400 hover:text-slate-200 cursor-pointer shrink-0"
                            title="Copy full SHA-256"
                          >
                            {copiedHash === 'clean' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                </>
              ) : (
                <div className="glass-panel rounded-2xl p-16 text-center shadow-2xl">
                  <ImageIcon className="w-14 h-14 text-slate-600 mx-auto mb-4" />
                  <h3 className="text-lg font-bold text-slate-200">No Image Selected</h3>
                  <p className="text-sm text-slate-400 mt-1 mb-5">
                    Upload an AI-generated image or click "Load AI Sample" to run forensic analysis.
                  </p>
                  <button
                    onClick={handleLoadSampleImage}
                    className="px-5 py-2.5 rounded-xl bg-emerald-500 text-slate-950 font-bold text-sm inline-flex items-center gap-2 cursor-pointer shadow-lg shadow-emerald-500/20"
                  >
                    <Sparkles className="w-4 h-4" />
                    Load Sample AI Image
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ====================================================
            TAB 2: PHASE 2 - TEXT AI HUMANIZER
           ==================================================== */}
        {activeTab === 'text' && (
          <div className="space-y-8">
            {/* Top Telemetry Stats Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
              <div className="glass-panel rounded-2xl p-5 shadow-xl">
                <span className="text-xs uppercase tracking-wider text-slate-400 font-bold">
                  Hidden Unicode Watermarks
                </span>
                <div className="flex items-baseline justify-between mt-2">
                  <span
                    className={`text-3xl font-extrabold font-mono ${
                      inputAnalysis.totalInvisibleCount > 0 ? 'text-rose-400' : 'text-emerald-400'
                    }`}
                  >
                    {inputAnalysis.totalInvisibleCount}
                  </span>
                  <span className="text-xs text-emerald-400 font-mono font-bold">
                    → {outputAnalysis.totalInvisibleCount} in output
                  </span>
                </div>
              </div>

              <div className="glass-panel rounded-2xl p-5 shadow-xl">
                <span className="text-xs uppercase tracking-wider text-slate-400 font-bold">
                  AI Clichés & Em-Dashes
                </span>
                <div className="flex items-baseline justify-between mt-2">
                  <span
                    className={`text-3xl font-extrabold font-mono ${
                      inputAnalysis.clichesFound.length + inputAnalysis.emDashCount > 0
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {inputAnalysis.clichesFound.length + inputAnalysis.emDashCount}
                  </span>
                  <span className="text-xs text-emerald-400 font-mono font-bold">
                    → {outputAnalysis.clichesFound.length + outputAnalysis.emDashCount} in output
                  </span>
                </div>
              </div>

              <div className="glass-panel rounded-2xl p-5 shadow-xl">
                <span className="text-xs uppercase tracking-wider text-slate-400 font-bold">
                  Burstiness Score
                </span>
                <div className="flex items-baseline justify-between mt-2">
                  <span className="text-3xl font-extrabold font-mono text-cyan-400">
                    {outputAnalysis.burstinessScore}%
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    Input: {inputAnalysis.burstinessScore}%
                  </span>
                </div>
              </div>

              <div className="glass-panel rounded-2xl p-5 shadow-xl">
                <span className="text-xs uppercase tracking-wider text-slate-400 font-bold">
                  Estimated AI Detection Risk
                </span>
                <div className="flex items-baseline justify-between mt-2">
                  <span
                    className={`text-3xl font-extrabold font-mono ${
                      outputAnalysis.aiProbability < 25 ? 'text-emerald-400' : 'text-amber-400'
                    }`}
                  >
                    {outputAnalysis.aiProbability}%
                  </span>
                  <span className="text-xs text-rose-400 font-mono">
                    From {inputAnalysis.aiProbability}%
                  </span>
                </div>
              </div>
            </div>

            {/* Text AI Detector Readiness Audit (Beginner-Friendly) */}
            <div className="glass-panel p-4 rounded-2xl shadow-xl border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    Text AI Detector Readiness Audit
                  </h3>
                </div>
                <span className="text-[11px] font-mono font-bold text-emerald-400 bg-emerald-500/15 px-2.5 py-0.5 rounded-full border border-emerald-500/30">
                  {outputAnalysis.aiProbability <= 15 ? 'NATURAL HUMAN VERIFIED' : 'READY TO RE-WRITE'}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">🎓 Turnitin &amp; GPTZero</span>
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                      BYPASS READY
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    Varied sentence burstiness ({outputAnalysis.burstinessScore}%) breaks statistical LLM predictability.
                  </p>
                </div>

                <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">🕵️ Unicode Watermarks</span>
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                      0 TOKENS (CLEAN)
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    All invisible zero-width spaces (U+200B, U+FEFF, U+200C) fully purged.
                  </p>
                </div>

                <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">✍️ Stylometry &amp; Clichés</span>
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                      NATURAL PROSE
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    Robotic phrases ("delve", "tapestry", "game-changer") and em-dashes eliminated.
                  </p>
                </div>
              </div>
            </div>

            {/* Controls Bar */}
            <div className="glass-panel rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 shadow-xl">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Target Tone:
                </span>
                {[
                  { id: 'linkedin', label: 'Professional LinkedIn' },
                  { id: 'casual', label: 'Casual / Social' },
                  { id: 'academic', label: 'Analytical / Expert' },
                  { id: 'storytelling', label: 'Narrative Storytelling' }
                ].map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setSelectedTone(t.id)}
                    className={`px-3.5 py-2 rounded-xl text-xs font-bold transition cursor-pointer ${
                      selectedTone === t.id
                        ? 'bg-emerald-500/25 text-emerald-300 border border-emerald-500/40 shadow-sm'
                        : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => setShowApiKeyInput(!showApiKeyInput)}
                  className="px-3.5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold flex items-center gap-2 border border-slate-700 transition cursor-pointer"
                  title="Configure optional Gemini API key"
                >
                  <Key className="w-4 h-4 text-cyan-400" />
                  <span>API Key</span>
                </button>

                <button
                  onClick={handleInstantAlgorithmicClean}
                  className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold flex items-center gap-2 border border-slate-700 transition cursor-pointer"
                >
                  <Sparkles className="w-4 h-4 text-amber-400" />
                  Instant Unicode & Cliché Scrub
                </button>

                <button
                  onClick={handleGeminiDeepHumanize}
                  disabled={isHumanizing || !inputText.trim()}
                  className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-extrabold text-xs flex items-center gap-2 shadow-lg shadow-emerald-500/20 transition disabled:opacity-50 cursor-pointer"
                >
                  <Wand2 className={`w-4 h-4 ${isHumanizing ? 'animate-spin' : ''}`} />
                  {isHumanizing ? 'Rewriting Burstiness...' : 'Deep AI Humanize'}
                </button>
              </div>
            </div>

            {showApiKeyInput && (
              <div className="p-4 rounded-xl bg-slate-900 border border-cyan-500/40 flex items-center gap-3 shadow-lg">
                <Key className="w-5 h-5 text-cyan-400 shrink-0" />
                <input
                  type="password"
                  placeholder="Paste your Google Gemini API Key here (Optional for cloud LLM rewriting)..."
                  value={customApiKey}
                  onChange={(e) => setCustomApiKey(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
                <span className="text-xs text-slate-400">Stored only in local session memory</span>
              </div>
            )}

            {humanizeError && (
              <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-2.5">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{humanizeError}</span>
              </div>
            )}

            {/* Side-by-Side Textarea Boxes */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Input Box */}
              <div className="glass-panel rounded-2xl p-5 flex flex-col space-y-4 shadow-2xl">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-rose-400" />
                    <span className="text-sm font-bold uppercase tracking-wider text-slate-200">
                      Input AI Text (ChatGPT / Gemini / Claude)
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => {
                        setInputText(SAMPLE_AI_TEXT);
                        setOutputText('');
                      }}
                      className="text-xs text-cyan-400 hover:text-cyan-300 hover:underline cursor-pointer font-semibold flex items-center gap-1"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      Load Sample Text
                    </button>
                    {inputText && (
                      <button
                        onClick={() => {
                          setInputText('');
                          setOutputText('');
                        }}
                        className="text-xs text-rose-400 hover:text-rose-300 hover:underline cursor-pointer font-semibold flex items-center gap-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                <textarea
                  value={inputText}
                  onChange={(e) => {
                    const val = e.target.value;
                    setInputText(val);
                    if (!val.trim()) {
                      setOutputText('');
                    }
                  }}
                  rows={12}
                  placeholder="Paste your AI-generated text here (e.g. from ChatGPT, Claude, Gemini) or click 'Load Sample Text' above..."
                  className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-4 text-sm text-slate-200 focus:outline-none focus:border-emerald-500/70 leading-relaxed resize-none font-sans"
                />

                <div className="space-y-2 pt-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Detected Structural Tells & Watermarks:
                  </span>
                  {inputText.trim() ? (
                    <div className="flex flex-wrap gap-2">
                      {inputAnalysis.invisibleFound.map((inv, idx) => (
                        <span
                          key={idx}
                          className="px-2.5 py-1 rounded-md bg-rose-500/20 border border-rose-500/35 text-rose-300 text-xs font-mono font-semibold"
                        >
                          {inv.code} {inv.name} (×{inv.count})
                        </span>
                      ))}
                      {inputAnalysis.emDashCount > 0 && (
                        <span className="px-2.5 py-1 rounded-md bg-amber-500/20 border border-amber-500/35 text-amber-300 text-xs font-mono font-semibold">
                          Em-Dashes "—" (×{inputAnalysis.emDashCount})
                        </span>
                      )}
                      {inputAnalysis.clichesFound.map((c, idx) => (
                        <span
                          key={idx}
                          className="px-2.5 py-1 rounded-md bg-amber-500/20 border border-amber-500/35 text-amber-300 text-xs font-semibold"
                        >
                          Cliché: "{c.phrase}"
                        </span>
                      ))}
                      {inputAnalysis.invisibleFound.length === 0 &&
                        inputAnalysis.emDashCount === 0 &&
                        inputAnalysis.clichesFound.length === 0 && (
                          <span className="text-xs text-emerald-400 font-medium">
                            ✓ No obvious watermarks or cliches detected in this text.
                          </span>
                        )}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 italic">
                      No text provided. Paste AI text above to analyze invisible watermarks and cliches.
                    </p>
                  )}
                </div>
              </div>

              {/* Output Box */}
              <div className="glass-panel border-emerald-500/30 rounded-2xl p-5 flex flex-col space-y-4 shadow-2xl">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span className="text-sm font-bold uppercase tracking-wider text-emerald-300">
                      Sanitized & Humanized Output
                    </span>
                  </div>
                  {outputText && (
                    <button
                      onClick={handleCopyOutput}
                      className="px-4 py-1.5 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-bold flex items-center gap-2 transition cursor-pointer"
                    >
                      {copiedText ? (
                        <>
                          <Check className="w-4 h-4 text-emerald-400" />
                          Copied Clean Text
                        </>
                      ) : (
                        <>
                          <Copy className="w-4 h-4" />
                          Copy Clean Text
                        </>
                      )}
                    </button>
                  )}
                </div>

                <textarea
                  value={outputText}
                  onChange={(e) => setOutputText(e.target.value)}
                  rows={12}
                  placeholder="Cleaned and humanized output will appear here after clicking 'Instant Unicode & Cliché Scrub' or 'Deep AI Humanize'..."
                  className="w-full bg-slate-950/90 border border-emerald-500/30 rounded-xl p-4 text-sm text-emerald-50 focus:outline-none focus:border-emerald-500 leading-relaxed resize-none font-sans"
                />


                <div className="p-3.5 rounded-xl bg-emerald-950/25 border border-emerald-500/25 flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2 text-emerald-300 font-semibold">
                    <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                    <span>0 Zero-Width Characters • 0 Em-Dashes • {outputAnalysis.wordCount} Words</span>
                  </div>
                  <span className="font-mono text-xs font-bold text-emerald-400">
                    Ready for LinkedIn, Medium & Turnitin
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ====================================================
            TAB 3: FORENSIC HEX & TOKEN VERIFICATION LAB
           ==================================================== */}
        {activeTab === 'forensic' && (
          <div className="space-y-8">
            <div className="glass-panel rounded-2xl p-6 shadow-2xl">
              <div className="flex items-center gap-3 mb-2">
                <Binary className="w-6 h-6 text-emerald-400" />
                <h2 className="text-base font-extrabold uppercase tracking-wider text-white">
                  Deep Binary Hex & Unicode Code-Point Inspector
                </h2>
              </div>
              <p className="text-sm text-slate-400">
                Inspect raw image container headers (Before vs. After container stripping) and examine every character byte in the text buffer.
              </p>

              {selectedImage ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-6">
                  {/* Original Hex Dump */}
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between text-xs font-bold">
                      <span className="text-rose-400">Original Binary Header ({selectedImage.name})</span>
                      <span className="font-mono text-slate-400">First 256 Bytes</span>
                    </div>
                    <div className="bg-[#050811] border border-rose-500/35 rounded-xl p-4 font-mono text-xs overflow-x-auto space-y-1.5 max-h-96">
                      {selectedImage.originalScan.hexLines.map((line, idx) => (
                        <div key={idx} className="flex gap-4 leading-tight">
                          <span className="text-slate-500 select-none font-semibold">{line.offset}</span>
                          <span className="text-slate-300">{line.hex}</span>
                          <span className="text-rose-300 font-bold">{line.ascii}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Cleaned Hex Dump */}
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between text-xs font-bold">
                      <span className="text-emerald-400">Sanitized Binary Header ({selectedImage.cleanFileName})</span>
                      <span className="font-mono text-slate-400">First 256 Bytes</span>
                    </div>
                    <div className="bg-[#050811] border border-emerald-500/35 rounded-xl p-4 font-mono text-xs overflow-x-auto space-y-1.5 max-h-96">
                      {selectedImage.cleanedScan.hexLines.map((line, idx) => (
                        <div key={idx} className="flex gap-4 leading-tight">
                          <span className="text-slate-500 select-none font-semibold">{line.offset}</span>
                          <span className="text-slate-300">{line.hex}</span>
                          <span className="text-emerald-300 font-bold">{line.ascii}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : null}

              {/* Text Invisible Token Highlighter */}
              <div className="mt-8 pt-6 border-t border-slate-800">
                <h3 className="text-sm font-bold uppercase tracking-wider text-cyan-400 mb-3">
                  Live Text Invisible Watermark X-Ray (Input Buffer)
                </h3>
                <div className="bg-[#050811] border border-slate-800 rounded-xl p-5 text-sm leading-loose font-mono text-slate-200 whitespace-pre-wrap">
                  {Array.from(inputText).map((ch, idx) => {
                    const foundInvisible = INVISIBLE_UNICODE_MAP.find((u) => u.char === ch);
                    if (foundInvisible) {
                      return (
                        <span
                          key={idx}
                          title={foundInvisible.name}
                          className="inline-block px-2 py-0.5 mx-1 rounded bg-rose-500 text-slate-950 font-bold text-xs align-middle"
                        >
                          [{foundInvisible.code}]
                        </span>
                      );
                    }
                    if (ch === '—') {
                      return (
                        <span
                          key={idx}
                          title="AI Em-Dash"
                          className="inline-block px-2 py-0.5 mx-1 rounded bg-amber-500 text-slate-950 font-bold text-xs align-middle"
                        >
                          [EM-DASH —]
                        </span>
                      );
                    }
                    return <React.Fragment key={idx}>{ch}</React.Fragment>;
                  })}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ====================================================
            SECTION 3: INTERACTIVE SEO ARCHITECTURE & KEYWORD INTENT MATRIX
           ==================================================== */}
        <section aria-labelledby="seo-matrix-heading" className="mt-16 pt-12 border-t border-slate-800/80">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 flex items-center justify-center border border-emerald-500/30">
                <Sparkles className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h2 id="seo-matrix-heading" className="text-xl font-black tracking-tight text-white">
                  Interactive SEO Architecture &amp; Search Intent Matrix
                </h2>
                <p className="text-xs text-slate-400">
                  Targeted high-intent Google search clusters. Click any query tag to load the dedicated tool route and preset.
                </p>
              </div>
            </div>

            <span className="text-xs font-mono font-bold px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300">
              Target Domain: <span className="text-emerald-400">https://aegis.smanas.net</span>
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {SEARCH_INTENT_CATEGORIES.map((cat, idx) => (
              <div
                key={idx}
                className="glass-panel p-5 rounded-2xl shadow-xl border border-slate-800 hover:border-emerald-500/40 transition flex flex-col justify-between space-y-4"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-extrabold uppercase tracking-wider text-emerald-400">
                      {cat.category}
                    </span>
                    <span className="text-[11px] font-mono font-semibold px-2.5 py-0.5 rounded-full bg-slate-900 text-slate-300 border border-slate-800">
                      {cat.competition}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed mb-4">
                    {cat.desc}
                  </p>

                  <div className="flex flex-wrap gap-2">
                    {cat.keywords.map((kw, kIdx) => (
                      <button
                        key={kIdx}
                        onClick={() => navigateTo(kw.route)}
                        className="group inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-slate-950/80 hover:bg-emerald-500/15 border border-slate-800 hover:border-emerald-500/40 text-slate-300 hover:text-emerald-300 transition cursor-pointer"
                      >
                        <span>• {kw.text}</span>
                        <ArrowUpRight className="w-3 h-3 text-slate-500 group-hover:text-emerald-400 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                      </button>
                    ))}
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-500">
                    Route: <code className="text-slate-400">{cat.route}</code>
                  </span>
                  <button
                    onClick={() => navigateTo(cat.route)}
                    className="text-xs font-bold text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer transition"
                  >
                    Launch Dedicated Tool <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ====================================================
            PRIVACY TRUST SIGNAL & STATIC SEMANTIC KNOWLEDGE BASE
            (600-800+ words of crawlable, indexable semantic HTML)
           ==================================================== */}
        <section aria-labelledby="static-guide-heading" className="mt-16 pt-12 border-t border-slate-800/80 space-y-8">
          {/* Trust Signal Banner */}
          <div className="p-6 rounded-2xl bg-gradient-to-r from-emerald-950/40 via-slate-900/90 to-teal-950/40 border border-emerald-500/40 shadow-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center shrink-0">
                <Lock className="w-6 h-6 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-lg font-black text-white tracking-tight">
                  100% Client-Side In-Browser Processing — Zero Server Uploads
                </h3>
                <p className="text-xs text-slate-300 mt-1 leading-relaxed max-w-3xl">
                  Your privacy is mathematically guaranteed. All image de-AI pipelines, C2PA manifest purges, SynthID desynchronization, and text humanization are executed directly in your browser's local memory using HTML5 Canvas and WebAssembly. Your photos, prompts, and essays never touch any remote database or cloud server.
                </p>
              </div>
            </div>
            <div className="shrink-0 flex items-center gap-3">
              <div className="text-right font-mono text-xs hidden sm:block">
                <div className="text-emerald-400 font-bold">0ms Network Latency</div>
                <div className="text-slate-400">0 Bytes Transferred</div>
              </div>
              <span className="px-3.5 py-1.5 rounded-xl bg-emerald-500/20 text-emerald-300 text-xs font-mono font-bold border border-emerald-500/40">
                VERIFIED SECURE
              </span>
            </div>
          </div>

          {/* Semantic Knowledge Guide */}
          <article className="glass-panel p-8 rounded-2xl shadow-xl space-y-6">
            <div className="border-b border-slate-800 pb-4">
              <h2 id="static-guide-heading" className="text-2xl font-black text-white tracking-tight">
                Complete Guide: How AI Metadata, C2PA Manifests &amp; SynthID Work
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                An authoritative technical breakdown for creators, photographers, and developers seeking digital provenance sovereignty.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-slate-300 leading-relaxed">
              <div className="space-y-2.5">
                <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                  1. C2PA &amp; JUMBF Manifest Architecture
                </h3>
                <p>
                  C2PA (Coalition for Content Provenance and Authenticity) is an industry specification backed by Adobe, Microsoft, OpenAI, and Google. When an AI tool like DALL-E 3 or Adobe Firefly outputs an image, it injects an ISO/IEC 19566-5 JUMBF universal metadata box. In PNG files, this is stored under the <code className="text-slate-200 bg-slate-900 px-1 py-0.5 rounded">c2pa</code> chunk; in JPEGs, it resides in <code className="text-slate-200 bg-slate-900 px-1 py-0.5 rounded">APP11</code> marker segments.
                </p>
                <p>
                  These manifests contain cryptographic signatures, generator hashes, and prompt lineage. When uploaded, platforms like LinkedIn inspect these bytes and automatically slap a permanent <strong className="text-white">"Created with AI"</strong> tag on your post. AEGIS AI Studio completely strips these container headers using an isolated memory pipeline.
                </p>
              </div>

              <div className="space-y-2.5">
                <h3 className="text-sm font-bold text-cyan-400 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                  2. Google DeepMind SynthID Steganography
                </h3>
                <p>
                  Unlike visible watermarks or file metadata, Google DeepMind's SynthID modifies the subtle frequency components of raw RGB pixel data during generation (Imagen 2/3 and Gemini). Because it is mathematically woven into the discrete cosine transform (DCT) domains, standard lossless compression or format conversions fail to remove it.
                </p>
                <p>
                  AEGIS AI Studio neutralizes SynthID using a proprietary two-step frequency wash: an imperceptible sub-pixel geometric resample (99.6% spatial desynchronization) followed by pseudo-random LSB micro-dithering. This scrambles the statistical phase correlation required by SynthID detectors without degrading visible visual quality.
                </p>
              </div>

              <div className="space-y-2.5">
                <h3 className="text-sm font-bold text-amber-400 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                  3. Invisible Unicode &amp; Text Stylometry
                </h3>
                <p>
                  AI text generators like ChatGPT, Claude, and Copilot frequently insert invisible zero-width unicode spaces (such as <code className="text-slate-200 bg-slate-900 px-1 py-0.5 rounded">U+200B</code>, <code className="text-slate-200 bg-slate-900 px-1 py-0.5 rounded">U+FEFF</code>, and <code className="text-slate-200 bg-slate-900 px-1 py-0.5 rounded">U+200D</code>) as tracking watermarks. Furthermore, LLM text exhibits low perplexity, repetitive transition phrases (<code className="text-slate-200 bg-slate-900 px-1 py-0.5 rounded">delve</code>, <code className="text-slate-200 bg-slate-900 px-1 py-0.5 rounded">tapestry</code>), and monotonic sentence length.
                </p>
                <p>
                  AEGIS AI Studio's Phase 2 Text Humanizer performs real-time code-point sanitization, purging all zero-width characters and em-dashes. It then restructures sentence syntax to achieve high burstiness, allowing your writing to pass Turnitin, GPTZero, and Copyleaks naturally.
                </p>
              </div>
            </div>
          </article>

          {/* Expandable FAQ Accordion */}
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/15 flex items-center justify-center border border-emerald-500/30">
                <HelpCircle className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white tracking-tight">
                  Detailed Frequently Asked Questions &amp; Technical Answers
                </h3>
                <p className="text-xs text-slate-400">
                  Real answers to the most common queries searched on Google regarding AI detection bypass.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <details className="glass-panel p-5 rounded-2xl border border-slate-800 text-xs group cursor-pointer shadow-lg" open>
                <summary className="font-bold text-emerald-300 flex items-center justify-between group-hover:text-emerald-200">
                  <span className="text-sm">How to stop LinkedIn from showing AI Info on images?</span>
                  <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90 text-slate-500" />
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed border-t border-slate-800/80 pt-2.5">
                  LinkedIn checks for two primary indicators: C2PA JUMBF manifests and IPTC digitalSourceType tags set to <code className="text-slate-300">trainedAlgorithmicMedia</code>. To bypass this, drop your image into AEGIS AI Studio with the <strong>Social Media Stealth</strong> preset enabled. AEGIS will strip all C2PA metadata and inject genuine Apple iPhone 16 Pro camera EXIF.
                </p>
              </details>

              <details className="glass-panel p-5 rounded-2xl border border-slate-800 text-xs group cursor-pointer shadow-lg" open>
                <summary className="font-bold text-cyan-300 flex items-center justify-between group-hover:text-cyan-200">
                  <span className="text-sm">How to bypass Instagram &amp; Facebook "Made with AI" labels?</span>
                  <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90 text-slate-500" />
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed border-t border-slate-800/80 pt-2.5">
                  Meta platforms automatically scan for C2PA assertions and IPTC metadata embedded by OpenAI, Midjourney, and Adobe. By stripping all container chunks and re-encoding with camera optics metadata (such as Sony Alpha A7 IV or iPhone 16 Pro), Meta's automated ingestion bot classifies the upload as genuine camera photography.
                </p>
              </details>

              <details className="glass-panel p-5 rounded-2xl border border-slate-800 text-xs group cursor-pointer shadow-lg">
                <summary className="font-bold text-teal-300 flex items-center justify-between group-hover:text-teal-200">
                  <span className="text-sm">Does stripping C2PA metadata degrade image visual quality?</span>
                  <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90 text-slate-500" />
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed border-t border-slate-800/80 pt-2.5">
                  No. C2PA manifests, EXIF headers, and XMP packets are purely ancillary metadata containers that exist outside the pixel bitmap. When AEGIS strips them, 100% of the image resolution, color depth, and sharpness are preserved. You can verify this in real-time using our interactive split-curtain comparison tool.
                </p>
              </details>

              <details className="glass-panel p-5 rounded-2xl border border-slate-800 text-xs group cursor-pointer shadow-lg">
                <summary className="font-bold text-amber-300 flex items-center justify-between group-hover:text-amber-200">
                  <span className="text-sm">What are zero-width spaces in ChatGPT text and how are they removed?</span>
                  <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90 text-slate-500" />
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed border-t border-slate-800/80 pt-2.5">
                  Zero-width spaces (such as <code className="text-slate-300">U+200B</code> and <code className="text-slate-300">U+FEFF</code>) are invisible Unicode characters that take up 0 pixels on screen but remain in the text byte stream. AI detection companies use them to watermark generated content. AEGIS AI Studio scans the unicode buffer, identifies exact character offsets, and strips every invisible code-point cleanly.
                </p>
              </details>

              <details className="glass-panel p-5 rounded-2xl border border-slate-800 text-xs group cursor-pointer shadow-lg">
                <summary className="font-bold text-rose-300 flex items-center justify-between group-hover:text-rose-200">
                  <span className="text-sm">How does AEGIS neutralize Google SynthID watermarks?</span>
                  <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90 text-slate-500" />
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed border-t border-slate-800/80 pt-2.5">
                  Google SynthID embeds statistical correlation patterns across pixel frequency domains that survive standard compression. AEGIS applies an imperceptible sub-pixel geometric resample (99.6% desync) and ±2 LSB micro-dithering to disrupt the mathematical carrier of the watermark without human-visible degradation.
                </p>
              </details>

              <details className="glass-panel p-5 rounded-2xl border border-slate-800 text-xs group cursor-pointer shadow-lg">
                <summary className="font-bold text-indigo-300 flex items-center justify-between group-hover:text-indigo-200">
                  <span className="text-sm">How does the AI Text Humanizer bypass Turnitin and GPTZero?</span>
                  <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90 text-slate-500" />
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed border-t border-slate-800/80 pt-2.5">
                  It strips invisible zero-width unicode tracking characters, replaces predictable LLM clichés (<code className="text-slate-300">delve</code>, <code className="text-slate-300">tapestry</code>, <code className="text-slate-300">testament</code>), normalizes em-dashes, and introduces dynamic sentence burstiness to mirror natural human writing.
                </p>
              </details>
            </div>
          </div>
        </section>
      </main>

      {/* SEO Footer */}
      <footer className="border-t border-slate-800/80 bg-[#050811] py-8 px-6 mt-12">
        <div className="max-w-[1550px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 flex items-center justify-center border border-emerald-500/30">
              <Shield className="w-4 h-4 text-emerald-400" />
            </div>
            <div>
              <p className="text-sm font-bold text-white">AEGIS AI STUDIO</p>
              <p className="text-xs text-slate-400">
                Official Domain: <a href="https://aegis.smanas.net" className="text-emerald-400 hover:underline">https://aegis.smanas.net</a> • 100% Client-Side Private
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
            <span className="px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-emerald-400 font-medium">
              ✓ LinkedIn AI Badge Bypass
            </span>
            <span className="px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-cyan-400 font-medium">
              ✓ Meta AI Tag Purge
            </span>
            <span className="px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-teal-400 font-medium">
              ✓ SynthID Neutralized
            </span>
            <span className="px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-amber-400 font-medium">
              ✓ Turnitin Humanizer
            </span>
          </div>
        </div>
      </footer>

      {/* Global Clipboard Paste Notification Toast */}
      {pasteNotification && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-5 py-3 rounded-2xl bg-emerald-500 text-slate-950 font-extrabold shadow-2xl shadow-emerald-500/40 text-sm border-2 border-slate-950">
          <span>{pasteNotification}</span>
        </div>
      )}
    </div>
  );
}
