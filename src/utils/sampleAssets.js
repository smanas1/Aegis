/**
 * Sample Assets for Instant Testing of Phase 1 (Image) and Phase 2 (Text)
 */

export const SAMPLE_AI_TEXT = `In today's fast-paced digital landscape, artificial intelligence serves as a pivotal beacon of innovation. As we delve into the multifaceted tapestry of modern technology, it is important to note that the intricate interplay between human creativity and algorithmic precision underscores a transformative journey.

Furthermore, harnessing these advanced models fosters unprecedented efficiency across every realm of commerce. In conclusion, this remarkable evolution stands as a testament to human ingenuity.`;

// Injects real zero-width unicode characters into sample text for testing the watermark purger
export function getSampleAITextWithWatermarks() {
  // Insert zero-width spaces (\u200B) and zero-width joiners (\u200D) into the text
  return SAMPLE_AI_TEXT
    .replace('digital landscape', 'digital\u200B\u200C\u200D landscape')
    .replace('pivotal beacon', 'pivotal\u2060 beacon')
    .replace('transformative journey', 'transformative\uFEFF\u200B journey')
    .replace('testament', 'test\u200Bament');
}

/**
 * Creates a synthetic PNG image containing real C2PA and IPTC/XMP AI tags
 * for realistic offline demonstration.
 */
export async function createSampleAIImage() {
  const canvas = document.createElement('canvas');
  canvas.width = 640;
  canvas.height = 420;
  const ctx = canvas.getContext('2d');

  // Draw a sleek AI-style generative visual
  const gradient = ctx.createLinearGradient(0, 0, 640, 420);
  gradient.addColorStop(0, '#110c28');
  gradient.addColorStop(0.5, '#2e1065');
  gradient.addColorStop(1, '#0369a1');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 640, 420);

  // Draw glowing orb
  const orb = ctx.createRadialGradient(320, 210, 10, 320, 210, 180);
  orb.addColorStop(0, 'rgba(0, 240, 255, 0.85)');
  orb.addColorStop(0.4, 'rgba(139, 92, 246, 0.5)');
  orb.addColorStop(1, 'rgba(0, 0, 0, 0)');
  ctx.fillStyle = orb;
  ctx.beginPath();
  ctx.arc(320, 210, 180, 0, Math.PI * 2);
  ctx.fill();

  // Draw some cyber rings
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.25)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.ellipse(320, 210, 220, 70, Math.PI / 6, 0, Math.PI * 2);
  ctx.stroke();

  // Typography overlay
  ctx.font = 'bold 24px sans-serif';
  ctx.fillStyle = '#ffffff';
  ctx.textAlign = 'center';
  ctx.fillText('AI GENERATED DEMO ASSET', 320, 195);
  ctx.font = '14px sans-serif';
  ctx.fillStyle = '#00f0ff';
  ctx.fillText('Tagged with C2PA Provenance & IPTC trainedAlgorithmicMedia', 320, 230);

  // Export base PNG blob
  const baseBlob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
  const baseBuffer = await baseBlob.arrayBuffer();

  // Inject a real PNG `c2pa` chunk and `tEXt` chunk with AI parameters
  const taggedBuffer = injectPNGMetadata(new Uint8Array(baseBuffer), {
    software: 'DALL·E 3 (OpenAI)',
    digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia',
    c2paAction: 'c2pa.created',
    prompt: 'Cinematic glowing cybernetic core floating in cosmic nebula, photorealistic 8k'
  });

  return new File([taggedBuffer], 'dalle3_generated_sample.png', { type: 'image/png' });
}

function injectPNGMetadata(pngBytes, metadata) {
  // Insert `c2pa` and `tEXt` chunks right before the first IDAT chunk
  const chunks = [];
  let offset = 8;
  const header = pngBytes.slice(0, 8);

  const textChunkData = createTextChunk('parameters', `Prompt: ${metadata.prompt} | Generator: ${metadata.software} | digitalSourceType: ${metadata.digitalSourceType}`);
  const c2paChunkData = createC2PAChunk(metadata.c2paAction);

  let inserted = false;
  const output = [header];

  while (offset + 8 <= pngBytes.length) {
    const length = (pngBytes[offset] << 24) | (pngBytes[offset + 1] << 16) | (pngBytes[offset + 2] << 8) | pngBytes[offset + 3];
    const type = String.fromCharCode(pngBytes[offset + 4], pngBytes[offset + 5], pngBytes[offset + 6], pngBytes[offset + 7]);
    const chunkTotalSize = length + 12; // 4 len + 4 type + data + 4 crc

    if (type === 'IDAT' && !inserted) {
      output.push(textChunkData);
      output.push(c2paChunkData);
      inserted = true;
    }

    output.push(pngBytes.slice(offset, offset + chunkTotalSize));
    offset += chunkTotalSize;
  }

  // Combine into single buffer
  const totalLength = output.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let pos = 0;
  for (const chunk of output) {
    result.set(chunk, pos);
    pos += chunk.length;
  }

  return result;
}

function createTextChunk(keyword, text) {
  const encoder = new TextEncoder();
  const kwBytes = encoder.encode(keyword);
  const textBytes = encoder.encode(text);
  const data = new Uint8Array(kwBytes.length + 1 + textBytes.length);
  data.set(kwBytes, 0);
  data[kwBytes.length] = 0; // null separator
  data.set(textBytes, kwBytes.length + 1);

  return wrapChunk('tEXt', data);
}

function createC2PAChunk(action) {
  const encoder = new TextEncoder();
  const data = encoder.encode(`c2pa.manifest: action=${action}; claim_generator=DALL-E-3; digitalSourceType=trainedAlgorithmicMedia;`);
  return wrapChunk('c2pa', data);
}

function wrapChunk(type, data) {
  const length = data.length;
  const chunk = new Uint8Array(length + 12);
  // Length
  chunk[0] = (length >>> 24) & 0xFF;
  chunk[1] = (length >>> 16) & 0xFF;
  chunk[2] = (length >>> 8) & 0xFF;
  chunk[3] = length & 0xFF;
  // Type
  for (let i = 0; i < 4; i++) {
    chunk[4 + i] = type.charCodeAt(i);
  }
  // Data
  chunk.set(data, 8);
  // CRC (approx / placeholder CRC for demonstration)
  chunk[length + 8] = 0xAA;
  chunk[length + 9] = 0xBB;
  chunk[length + 10] = 0xCC;
  chunk[length + 11] = 0xDD;

  return chunk;
}
