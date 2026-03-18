/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        mc: {
          bg0: '#050a18', bg1: '#0a1128', bg2: '#0f1a38', bg3: '#162450', bg4: '#1d3060',
          brand: '#2d7aff', brandLight: '#5a9aff', cyan: '#22d3ee', emerald: '#34d399',
          amber: '#fbbf24', rose: '#fb7185', orange: '#f97316',
          txt: '#e8edf8', txt2: '#8ea0c4', txt3: '#536b8e',
          card: '#0c1630', cardBorder: '#1a2d55',
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans Hebrew"', '"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      backgroundImage: {
        'hero-gradient': 'linear-gradient(160deg, #0a1a40 0%, #0f2560 40%, #1a3a80 70%, #1050aa 100%)',
        'nav-gradient': 'linear-gradient(180deg, #0a1128 0%, #0e1a38 100%)',
      },
    },
  },
  plugins: [],
};
