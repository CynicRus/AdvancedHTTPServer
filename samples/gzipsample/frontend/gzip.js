document.write('<script src="https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js"><\/script>');

window.gzip = {
  compressToUint8: async (str) => {
    const buf = new TextEncoder().encode(str);
    return pako.gzip(buf); // Uint8Array
  },

  decompressFromUint8: async (u8) => {
    return pako.ungzip(u8, { to: 'string' });
  }
};