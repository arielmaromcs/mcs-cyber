/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        mc: {
          bg0: '#060a14', bg1: '#0b1224', bg2: '#111d36', bg3: '#182645', bg4: '#203060',
          brand: '#3b8bff', cyan: '#22d3ee', emerald: '#34d399', amber: '#fbbf24', rose: '#fb7185',
          txt: '#e2e8f5', txt2: '#8498bb', txt3: '#4b6080',
        },
      },
      fontFamily: {
        sans: ['IBM Plex Sans', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
};
