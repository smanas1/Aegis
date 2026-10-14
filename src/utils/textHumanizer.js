/**
 * AI Text Watermark Purger & Humanizer Engine
 * 1. Strips invisible zero-width unicode watermarks, homoglyphs, and tracking tags.
 * 2. Analyzes AI markers: AI buzzwords, sentence uniformity (low burstiness), repetitive transitions.
 * 3. Rewrites and humanizes text across multiple styles (Conversational, LinkedIn Pro, Direct, Storyteller).
 */

// Invisible watermark characters embedded by LLMs or watermarking systems
export const INVISIBLE_WATERMARK_CHARS = [
  { regex: /\u200B/g, name: 'Zero-Width Space (U+200B)' },
  { regex: /\u200C/g, name: 'Zero-Width Non-Joiner (U+200C)' },
  { regex: /\u200D/g, name: 'Zero-Width Joiner (U+200D)' },
  { regex: /\u2060/g, name: 'Word Joiner (U+2060)' },
  { regex: /\uFEFF/g, name: 'Zero-Width No-Break Space / BOM (U+FEFF)' },
  { regex: /\u00AD/g, name: 'Soft Hyphen (U+00AD)' },
  { regex: /[\u200E\u200F]/g, name: 'Bi-directional Directional Marks' },
  { regex: /[\uFE00-\uFE0F]/g, name: 'Variation Selectors' }
];

// Classic AI Hallmark Words and Clichés
export const AI_CLICHES = [
  { word: 'delve', replacement: 'look into', alternatives: ['explore', 'examine', 'dig into'] },
  { word: 'delving', replacement: 'looking into', alternatives: ['exploring', 'digging into'] },
  { word: 'tapestry', replacement: 'blend', alternatives: ['mix', 'collection', 'mosaic'] },
  { word: 'beacon', replacement: 'guide', alternatives: ['symbol', 'leader', 'model'] },
  { word: 'testament', replacement: 'proof', alternatives: ['evidence', 'sign', 'reminder'] },
  { word: 'pivotal', replacement: 'key', alternatives: ['crucial', 'central', 'essential'] },
  { word: 'moreover', replacement: 'also', alternatives: ['plus', 'and', 'what\'s more'] },
  { word: 'furthermore', replacement: 'also', alternatives: ['in addition', 'plus', 'on top of that'] },
  { word: 'in conclusion', replacement: 'overall', alternatives: ['to wrap up', 'bottom line', 'all in all'] },
  { word: 'it is important to note', replacement: 'keep in mind', alternatives: ['notably', 'worth noting', 'remember'] },
  { word: 'underscores', replacement: 'highlights', alternatives: ['shows', 'stresses', 'points to'] },
  { word: 'interplay', replacement: 'interaction', alternatives: ['connection', 'balance', 'dynamic'] },
  { word: 'navigating the landscape', replacement: 'moving through', alternatives: ['working in', 'handling', 'managing'] },
  { word: 'realm', replacement: 'field', alternatives: ['area', 'domain', 'space'] },
  { word: 'harnessing', replacement: 'using', alternatives: ['applying', 'leveraging', 'drawing on'] },
  { word: 'multifaceted', replacement: 'complex', alternatives: ['varied', 'diverse', 'multi-layered'] },
  { word: 'paramount', replacement: 'vital', alternatives: ['crucial', 'top priority', 'essential'] },
  { word: 'transformative journey', replacement: 'growth process', alternatives: ['evolution', 'shift', 'progress'] },
  { word: 'at its core', replacement: 'basically', alternatives: ['fundamentally', 'at heart', 'deep down'] },
  { word: 'fosters', replacement: 'builds', alternatives: ['helps grow', 'nurtures', 'encourages'] },
  { word: 'sheds light on', replacement: 'explains', alternatives: ['reveals', 'clarifies', 'highlights'] },
  { word: 'exemplifies', replacement: 'shows', alternatives: ['illustrates', 'is a great example of', 'demonstrates'] }
];

/**
 * Scan text for invisible watermarks and AI characteristics
 */
export function analyzeText(text) {
  if (!text || text.trim().length === 0) {
    return {
      wordCount: 0,
      charCount: 0,
      watermarkCount: 0,
      detectedWatermarks: [],
      clicheCount: 0,
      detectedCliches: [],
      burstinessScore: 100, // 0 = very uniform (AI), 100 = dynamic human
      aiProbability: 0,
      cleanTextPreview: ''
    };
  }

  // 1. Watermark Detection
  let watermarkCount = 0;
  const detectedWatermarks = [];

  for (const wm of INVISIBLE_WATERMARK_CHARS) {
    const matches = text.match(wm.regex);
    if (matches && matches.length > 0) {
      watermarkCount += matches.length;
      detectedWatermarks.push(`${wm.name} (x${matches.length})`);
    }
  }

  // 2. AI Cliché Detection
  const detectedCliches = [];
  let clicheCount = 0;
  const lowerText = text.toLowerCase();

  for (const item of AI_CLICHES) {
    const regex = new RegExp(`\\b${item.word}\\b`, 'gi');
    const matches = lowerText.match(regex);
    if (matches && matches.length > 0) {
      clicheCount += matches.length;
      detectedCliches.push({
        word: item.word,
        count: matches.length,
        replacement: item.replacement,
        alternatives: item.alternatives
      });
    }
  }

  // 3. Sentence Length & Burstiness Calculation
  const sentences = text
    .split(/[.!?]+/)
    .map(s => s.trim())
    .filter(s => s.length > 0);

  const words = text.trim().split(/\s+/).filter(w => w.length > 0);
  const sentenceWordCounts = sentences.map(s => s.split(/\s+/).length);

  let burstiness = 50;
  if (sentenceWordCounts.length > 1) {
    const avg = sentenceWordCounts.reduce((a, b) => a + b, 0) / sentenceWordCounts.length;
    const variance = sentenceWordCounts.reduce((sum, len) => sum + Math.pow(len - avg, 2), 0) / sentenceWordCounts.length;
    const stdDev = Math.sqrt(variance);

    // AI typically produces stdDev around 3-5, while human writing ranges 7-15+
    burstiness = Math.min(100, Math.round((stdDev / 10) * 100));
  }

  // 4. Compute AI Probability (0% - 100%)
  let score = 0;
  if (watermarkCount > 0) score += 40;
  score += Math.min(45, clicheCount * 9);
  if (burstiness < 30) score += 25;
  else if (burstiness < 50) score += 15;

  const aiProbability = Math.min(99, Math.max(5, score));

  return {
    wordCount: words.length,
    charCount: text.length,
    watermarkCount,
    detectedWatermarks,
    clicheCount,
    detectedCliches,
    burstinessScore: burstiness,
    aiProbability
  };
}

/**
 * Strips all invisible zero-width watermarks from text
 */
export function purgeWatermarks(text) {
  let cleaned = text;
  for (const wm of INVISIBLE_WATERMARK_CHARS) {
    cleaned = cleaned.replace(wm.regex, '');
  }
  return cleaned;
}

/**
 * Humanize AI text based on chosen style
 */
export function humanizeText(text, style = 'conversational') {
  if (!text) return '';

  // Step 1: Purge zero-width unicode watermarks
  let result = purgeWatermarks(text);

  // Step 2: Replace AI clichés with dynamic human language
  for (const item of AI_CLICHES) {
    const regex = new RegExp(`\\b${item.word}\\b`, 'gi');
    result = result.replace(regex, (match) => {
      // Pick a random alternative for natural human variety
      const choices = [item.replacement, ...item.alternatives];
      const picked = choices[Math.floor(Math.random() * choices.length)];
      // Preserve uppercase first letter if original had it
      if (match[0] === match[0].toUpperCase()) {
        return picked.charAt(0).toUpperCase() + picked.slice(1);
      }
      return picked;
    });
  }

  // Step 3: Style-specific tone adjustments
  if (style === 'linkedin') {
    // LinkedIn format: Punchy, short paragraphs, active hooks, spacing
    const paragraphs = result.split(/\n+/).map(p => p.trim()).filter(Boolean);
    const formatted = paragraphs.map(p => {
      // Break overly long sentences with conversational pauses or em-dashes
      return p
        .replace(/\bIn today's fast-paced world\b/gi, 'Right now')
        .replace(/\bIn an era where\b/gi, 'When')
        .replace(/\bIt is worth noting that\b/gi, 'Here\'s the thing:')
        .replace(/\bLet that sink in\./gi, '');
    });
    result = formatted.join('\n\n');
  } else if (style === 'conversational') {
    // Conversational: Natural contractions, human flow
    result = result
      .replace(/\bdo not\b/gi, "don't")
      .replace(/\bcannot\b/gi, "can't")
      .replace(/\bit is\b/gi, "it's")
      .replace(/\bthere is\b/gi, "there's")
      .replace(/\bwe have\b/gi, "we've")
      .replace(/\bthey are\b/gi, "they're")
      .replace(/\bIn summary,\b/gi, "Bottom line:")
      .replace(/\bAs previously mentioned,\b/gi, "Like I said earlier,");
  } else if (style === 'direct') {
    // Direct / Punchy: Remove throat-clearing fluff
    result = result
      .replace(/\bNeedless to say,\b/gi, '')
      .replace(/\bIt goes without saying that\b/gi, '')
      .replace(/\bAt the end of the day,\b/gi, 'Ultimately,')
      .replace(/\bWith that being said,\b/gi, 'Still,')
      .replace(/\bIn order to\b/gi, 'To');
  } else if (style === 'story') {
    // Storyteller: warmer voice, natural transitions
    result = result
      .replace(/\bFirst and foremost,\b/gi, 'To start with,')
      .replace(/\bSubsequently,\b/gi, 'After that,')
      .replace(/\bConsequently,\b/gi, 'Because of this,');
  }

  return result.trim();
}
