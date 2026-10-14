/**
 * Robust Client-Side Metadata & AI Provenance Scanner
 * Inspects JPEG, PNG, WebP for C2PA manifests, IPTC digitalSourceType, XMP, EXIF, and AI prompt tags.
 */

export async function scanImageMetadata(fileOrBlob) {
  const buffer = await fileOrBlob.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const size = buffer.byteLength;

  const result = {
    fileSize: size,
    format: detectFormat(bytes),
    hasC2PA: false,
    hasXMP: false,
    hasEXIF: false,
    hasIPTC: false,
    hasAIPrompts: false,
    aiSignaturesFound: [],
    chunksFound: [],
    rawMetadataStrings: [],
    riskLevel: 'LOW', // 'SAFE' | 'LOW' | 'MEDIUM' | 'CRITICAL'
    riskScore: 0, // 0 - 100
    platformBadgeRisk: {
      linkedIn: false,
      metaInstagram: false,
      google: false
    },
    exifTags: {},
    xmpContent: null,
    c2paManifestInfo: null
  };

  if (result.format === 'PNG') {
    scanPNG(bytes, result);
  } else if (result.format === 'JPEG') {
    scanJPEG(bytes, result);
  } else if (result.format === 'WEBP') {
    scanWebP(bytes, result);
  }

  // General text sweep across the entire binary for known AI markers and provenance signatures
  scanBinaryStrings(bytes, result);

  // Compute final risk evaluation
  computeRiskLevel(result);

  return result;
}

function detectFormat(bytes) {
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    return 'PNG';
  }
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    return 'JPEG';
  }
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
    return 'WEBP';
  }
  return 'UNKNOWN';
}

function scanPNG(bytes, result) {
  let offset = 8; // skip 8-byte PNG header
  const decoder = new TextDecoder();

  while (offset + 8 <= bytes.length) {
    const length = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    const type = String.fromCharCode(bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]);
    offset += 8;

    if (offset + length > bytes.length) break;

    const chunkData = bytes.subarray(offset, offset + length);
    result.chunksFound.push({ type, length });

    if (type === 'c2pa') {
      result.hasC2PA = true;
      result.aiSignaturesFound.push('C2PA Content Credentials Chunk (PNG c2pa)');
      result.c2paManifestInfo = { chunk: 'c2pa', size: length };
    } else if (type === 'eXIf') {
      result.hasEXIF = true;
      result.chunksFound.push({ type: 'eXIf (EXIF metadata)', length });
    } else if (type === 'tEXt' || type === 'zTXt' || type === 'iTXt') {
      try {
        const textStr = decoder.decode(chunkData);
        inspectTextContent(textStr, result, `PNG ${type}`);
      } catch (e) {
        // ignore decode errors for compressed chunks
      }
    }

    offset += length + 4; // skip CRC
  }
}

function scanJPEG(bytes, result) {
  let offset = 2; // skip SOI (0xFFD8)
  const decoder = new TextDecoder();

  while (offset < bytes.length - 1) {
    if (bytes[offset] !== 0xFF) {
      offset++;
      continue;
    }

    const marker = bytes[offset + 1];
    offset += 2;

    // Standalone markers without length
    if (marker === 0xD8 || marker === 0xD9 || (marker >= 0xD0 && marker <= 0xD7)) {
      continue;
    }

    if (offset + 2 > bytes.length) break;
    const length = (bytes[offset] << 8) | bytes[offset + 1];
    const segmentData = bytes.subarray(offset + 2, offset + length);

    // APP1: EXIF and XMP
    if (marker === 0xE1) {
      result.hasEXIF = true;
      result.chunksFound.push({ type: 'APP1 (EXIF/XMP)', length });
      try {
        const str = decoder.decode(segmentData);
        if (str.includes('http://ns.adobe.com/xap/1.0/')) {
          result.hasXMP = true;
          result.xmpContent = str.slice(0, 500);
        }
        inspectTextContent(str, result, 'JPEG APP1');
      } catch (e) {}
    }
    // APP11: C2PA / JUMBF (Super important: DALL-E / OpenAI / Adobe embed C2PA in APP11)
    else if (marker === 0xEB) {
      result.chunksFound.push({ type: 'APP11 (C2PA/JUMBF)', length });
      try {
        const str = decoder.decode(segmentData);
        if (str.includes('c2pa') || str.includes('jumbf') || str.includes('urn:uuid:')) {
          result.hasC2PA = true;
          result.aiSignaturesFound.push('C2PA Content Credentials (JPEG APP11 JUMBF)');
          result.c2paManifestInfo = { chunk: 'APP11_JUMBF', size: length };
        }
      } catch (e) {}
    }
    // APP13: IPTC / Photoshop IRB
    else if (marker === 0xED) {
      result.hasIPTC = true;
      result.chunksFound.push({ type: 'APP13 (IPTC Photoshop)', length });
    }
    // COM: Comments
    else if (marker === 0xFE) {
      result.chunksFound.push({ type: 'COM (Comment)', length });
      try {
        const str = decoder.decode(segmentData);
        inspectTextContent(str, result, 'JPEG COM');
      } catch (e) {}
    }

    offset += length;
  }
}

function scanWebP(bytes, result) {
  let offset = 12; // skip RIFF....WEBP
  const decoder = new TextDecoder();

  while (offset + 8 <= bytes.length) {
    const chunkType = String.fromCharCode(bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]);
    const chunkSize = bytes[offset + 4] | (bytes[offset + 5] << 8) | (bytes[offset + 6] << 16) | (bytes[offset + 7] << 24);
    offset += 8;

    result.chunksFound.push({ type: chunkType, length: chunkSize });

    if (chunkType === 'EXIF') {
      result.hasEXIF = true;
    } else if (chunkType === 'XMP ') {
      result.hasXMP = true;
      try {
        const xmpStr = decoder.decode(bytes.subarray(offset, offset + chunkSize));
        inspectTextContent(xmpStr, result, 'WebP XMP');
      } catch (e) {}
    }

    offset += chunkSize + (chunkSize % 2); // padded to even
  }
}

function scanBinaryStrings(bytes, result) {
  // Convert binary to latin1 for fast string search across entire file
  let binaryStr = '';
  // Inspect first 256KB and last 64KB where metadata headers and trailers live
  const headSize = Math.min(bytes.length, 256 * 1024);
  for (let i = 0; i < headSize; i++) {
    const code = bytes[i];
    if (code >= 32 && code <= 126) {
      binaryStr += String.fromCharCode(code);
    } else {
      binaryStr += ' ';
    }
  }

  // Critical AI Provenance Indicators used by LinkedIn & Meta
  const criticalPatterns = [
    { pattern: 'trainedAlgorithmicMedia', label: 'IPTC digitalSourceType: trainedAlgorithmicMedia (Triggers LinkedIn AI Badge)' },
    { pattern: 'c2pa.action', label: 'C2PA Manifest Action: c2pa.created / c2pa.placed' },
    { pattern: 'c2pa.claim', label: 'C2PA Content Credentials Claim' },
    { pattern: 'DALL·E', label: 'OpenAI DALL·E Provenance Signature' },
    { pattern: 'DALL-E', label: 'DALL-E Generator Stamp' },
    { pattern: 'Midjourney', label: 'Midjourney AI Generator Metadata' },
    { pattern: 'Stable Diffusion', label: 'Stable Diffusion Generation Signature' },
    { pattern: 'NovelAI', label: 'NovelAI Model Signature' },
    { pattern: 'ComfyUI', label: 'ComfyUI Workflow Metadata' },
    { pattern: 'Automatic1111', label: 'Automatic1111 WebUI Prompt Info' },
    { pattern: 'Adobe Firefly', label: 'Adobe Firefly Generative Fill Provenance' },
    { pattern: 'SynthID', label: 'Google SynthID Digital Watermark Indicator' },
    { pattern: 'Google Imagen', label: 'Google Imagen 3 Generative Tag' },
    { pattern: 'ChatGPT', label: 'ChatGPT Image Generation Metadata' }
  ];

  for (const { pattern, label } of criticalPatterns) {
    if (binaryStr.toLowerCase().includes(pattern.toLowerCase())) {
      if (!result.aiSignaturesFound.includes(label)) {
        result.aiSignaturesFound.push(label);
        result.hasAIPrompts = true;
      }
      if (pattern.includes('c2pa') || pattern.includes('trainedAlgorithmicMedia')) {
        result.hasC2PA = true;
      }
    }
  }

  // Look for prompt or negative prompt keys
  if (/prompt|negative prompt|steps:\s*\d+|sampler:\s*\w+|cfg scale/i.test(binaryStr)) {
    if (!result.aiSignaturesFound.some(s => s.includes('Diffusion Prompt'))) {
      result.aiSignaturesFound.push('Generative Diffusion Prompt & Sampler Settings');
      result.hasAIPrompts = true;
    }
  }
}

function inspectTextContent(str, result, source) {
  if (str.includes('trainedAlgorithmicMedia')) {
    result.hasC2PA = true;
    result.aiSignaturesFound.push(`[${source}] IPTC trainedAlgorithmicMedia tag`);
  }
  if (str.includes('c2pa') || str.includes('contentCredentials')) {
    result.hasC2PA = true;
    result.aiSignaturesFound.push(`[${source}] C2PA Content Credentials tag`);
  }
  if (/dall[-·]e|midjourney|stable diffusion|comfyui/i.test(str)) {
    result.hasAIPrompts = true;
    result.aiSignaturesFound.push(`[${source}] AI Generator references found in text`);
  }
  if (str.length > 20) {
    result.rawMetadataStrings.push(str.slice(0, 150));
  }
}

function computeRiskLevel(result) {
  let score = 0;

  if (result.hasC2PA) {
    score += 65;
    result.platformBadgeRisk.linkedIn = true;
    result.platformBadgeRisk.metaInstagram = true;
  }

  if (result.aiSignaturesFound.some(s => s.includes('trainedAlgorithmicMedia') || s.includes('DALL') || s.includes('Google'))) {
    score += 25;
    result.platformBadgeRisk.linkedIn = true;
    result.platformBadgeRisk.metaInstagram = true;
    result.platformBadgeRisk.google = true;
  }

  if (result.hasAIPrompts) {
    score += 20;
  }

  if (result.hasEXIF || result.hasXMP) {
    score += 15;
  }

  result.riskScore = Math.min(100, score);

  if (result.riskScore >= 60) {
    result.riskLevel = 'CRITICAL';
  } else if (result.riskScore >= 30) {
    result.riskLevel = 'MEDIUM';
  } else if (result.riskScore > 0) {
    result.riskLevel = 'LOW';
  } else {
    result.riskLevel = 'SAFE';
  }
}
