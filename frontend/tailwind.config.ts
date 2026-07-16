import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Signature accent
        acid: '#00e676',
        // Severity
        crit: '#ff1744',
        high:  '#ff6d00',
        med:   '#ffd600',
        low:   '#00b0ff',
        // Background surfaces
        void: '#030810',
        surface: {
          0: '#070f1a',
          1: '#0c1624',
          2: '#111e2e',
          3: '#172436',
        },
        // Borders
        wire: {
          0: '#0f1e2f',
          1: '#162a3e',
          2: '#1f3f5a',
          3: '#2a5070',
        },
        // Text
        ink: {
          0: '#daeeff',
          1: '#8aaac8',
          2: '#4a6a88',
          3: '#2a4060',
        },
      },
      fontFamily: {
        rajdhani: ['var(--font-rajdhani)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'acid-sm': '0 0 12px rgba(0, 230, 118, 0.18)',
        'acid-md': '0 0 24px rgba(0, 230, 118, 0.25)',
        'crit-sm': '0 0 12px rgba(255, 23, 68, 0.25)',
        'high-sm': '0 0 12px rgba(255, 109, 0, 0.20)',
        'glow-in': 'inset 0 1px 0 rgba(255,255,255,0.04)',
      },
      animation: {
        'spin-slow': 'spin 8s linear infinite',
        'pulse-acid': 'pulse-acid 2s ease-in-out infinite',
        'blink': 'blink 1.2s step-end infinite',
        'fade-in-up': 'fade-in-up 0.5s ease-out both',
        'slide-in': 'slide-in 0.4s ease-out both',
        'count-up': 'count-up 0.6s ease-out both',
        'scan': 'scan 4s linear infinite',
        'flicker': 'flicker 8s ease-in-out infinite',
      },
      keyframes: {
        'pulse-acid': {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(0, 230, 118, 0)' },
          '50%': { boxShadow: '0 0 0 6px rgba(0, 230, 118, 0)' },
        },
        'blink': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        'fade-in-up': {
          from: { opacity: '0', transform: 'translateY(10px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in': {
          from: { opacity: '0', transform: 'translateX(-6px)' },
          to: { opacity: '1', transform: 'translateX(0)' },
        },
        'count-up': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'scan': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'flicker': {
          '0%, 94%, 96%, 98%, 100%': { opacity: '1' },
          '95%': { opacity: '0.82' },
          '97%': { opacity: '0.9' },
          '99%': { opacity: '0.85' },
        },
      },
    },
  },
  plugins: [],
}
export default config
