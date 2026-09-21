/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Anvesh Color Tokens
        anvesh: {
          darkBg: '#080C12',
          darkSurface: '#0F151D',
          darkElevated: '#151D27',
          darkBorder: '#25313E',
          darkText: '#E8EDF3',
          darkSecondary: '#8996A6',
          
          lightBg: '#F4F7FA',
          lightSurface: '#FFFFFF',
          lightSecondary: '#EEF2F6',
          lightBorder: '#D5DDE6',
          lightText: '#17212B',
          lightTextSecondary: '#5F6B78',

          brand: '#5B8DEF',
          brandLight: '#315EAA',
          investigation: '#8B7CF6',
          investigationLight: '#6657C7',
          verified: '#35C98A',
          verifiedLight: '#167A59',
          suspicious: '#F2B84B',
          suspiciousLight: '#9A6500',
          critical: '#EF6262',
          criticalLight: '#C53D3D',
        }
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['IBM Plex Mono', 'JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'subtle': '0 1px 2px 0 rgba(0, 0, 0, 0.25)',
        'elevated': '0 4px 12px 0 rgba(0, 0, 0, 0.35)',
      }
    },
  },
  plugins: [],
}
