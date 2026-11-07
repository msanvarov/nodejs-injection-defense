// UNSAFE: nested quantifiers. On input like 'aaaa...a!' the engine tries
// every way to split the letters into words, which is exponential: each extra
// letter doubles the time. 30 letters blocks the event loop for ~20 seconds.
export const isWordListUnsafe = (s) => /^(\w+\s?)*$/.test(s);

// SAFE: no ambiguity (each space must be followed by a word, so there is only
// one way to match). Also rejects a trailing space, which the unsafe one allowed.
// Plus a length cap so even a linear regex has bounded work.
const MAX_LEN = 1000;
export const isWordList = (s) => s.length <= MAX_LEN && /^(\w+(\s\w+)*)?$/.test(s);
