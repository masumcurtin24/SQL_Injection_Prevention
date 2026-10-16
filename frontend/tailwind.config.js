// frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
const defaultTheme = require('tailwindcss/defaultTheme'); // For extending default fonts

module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'dark-primary': '#0D1117',
        'dark-secondary': '#161B22',
        'dark-tertiary': '#21262D',
        'border-dark': '#30363D',
        'border-light': '#484F58',
        'text-primary': '#C9D1D9',
        'text-secondary': '#8B949E',
        'text-accent': '#58A6FF',
        'accent-cyan': {
          DEFAULT: '#22d3ee', '300': '#67e8f9', '500': '#06b6d4', '600': '#0891b2', 'contrast': '#0f172a',
        },
        'accent-green': {
          DEFAULT: '#22c55e', 'bg': 'rgba(34, 197, 94, 0.1)', 'border': 'rgba(34, 197, 94, 0.3)', 'text': '#86efac',
        },
        'accent-red': {
          DEFAULT: '#ef4444', 'bg': 'rgba(239, 68, 68, 0.1)', 'border': 'rgba(239, 68, 68, 0.3)', 'text': '#fca5a5',
        },
        'accent-orange': {
          DEFAULT: '#f97316', 'bg': 'rgba(249, 115, 22, 0.1)', 'border': 'rgba(249, 115, 22, 0.3)', 'text': '#fdba74',
        },
        'accent-yellow': {
          DEFAULT: '#eab308', 'bg': 'rgba(234, 179, 8, 0.1)', 'border': 'rgba(234, 179, 8, 0.3)', 'text': '#fef08a',
        },
        // You can rely on Tailwind's default slate palette or define your own if needed.
      },
      fontFamily: {
        sans: ['"Manrope"', '"Space Grotesk"', ...defaultTheme.fontFamily.sans],
        mono: ['Roboto Mono', ...defaultTheme.fontFamily.mono],
      },
      animation: { // Keep animations if you use them
        fadeIn: 'fadeIn 0.5s ease-out forwards',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        }
      }
    },
  },
  plugins: [
    // require('@tailwindcss/forms'),
  ],
}
