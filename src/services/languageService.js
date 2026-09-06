const LANGUAGE_PATTERNS = {
  English: /[a-zA-Z]/g,
  Telugu: /[\u0C00-\u0C7F]/g,
  Hindi: /[\u0900-\u097F]/g,
  Tamil: /[\u0B80-\u0BFF]/g,
  Kannada: /[\u0C80-\u0CFF]/g,
  Malayalam: /[\u0D00-\u0D7F]/g,
};

function countCharacters(text, pattern) {
  const matches = text.match(pattern);
  return matches ? matches.length : 0;
}

export function detectLanguage(text = "") {
  const languageCounts = Object.entries(LANGUAGE_PATTERNS).map(
    ([language, pattern]) => ({
      language,
      count: countCharacters(text, pattern),
    })
  );

  languageCounts.sort((a, b) => b.count - a.count);

  const detectedLanguage = languageCounts[0];

  if (!detectedLanguage || detectedLanguage.count === 0) {
    return "Unknown";
  }

  return detectedLanguage.language;
}