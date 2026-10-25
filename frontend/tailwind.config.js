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
        surface: {
          DEFAULT: '#101416',
          dim: '#101416',
          bright: '#363a3c',
          variant: '#323538',
        },
        'surface-container': {
          lowest: '#0b0f11',
          low: '#191c1e',
          DEFAULT: '#1d2022',
          high: '#272a2d',
          highest: '#323538',
        },
        'on-surface': {
          DEFAULT: '#e0e3e6',
          variant: '#bdc9c3',
        },
        'inverse-surface': {
          DEFAULT: '#e0e3e6',
          'on': '#2d3133',
        },
        outline: {
          DEFAULT: '#87938e',
          variant: '#3e4945',
        },
        primary: {
          DEFAULT: '#78d8ba',
          tint: '#78d8ba',
          container: '#3da186',
          fixed: '#94f5d6',
          'fixed-dim': '#78d8ba',
        },
        'on-primary': {
          DEFAULT: '#00382b',
          container: '#003025',
          fixed: '#002018',
          'fixed-variant': '#005140',
        },
        'inverse-primary': '#006b55',
        secondary: {
          DEFAULT: '#81d0f8',
          container: '#017094',
          fixed: '#c1e8ff',
          'fixed-dim': '#81d0f8',
        },
        'on-secondary': {
          DEFAULT: '#003548',
          container: '#ceedff',
          fixed: '#001e2b',
          'fixed-variant': '#004d67',
        },
        tertiary: {
          DEFAULT: '#a7c8ff',
          container: '#6d92cb',
          fixed: '#d5e3ff',
          'fixed-dim': '#a7c8ff',
        },
        'on-tertiary': {
          DEFAULT: '#003060',
          container: '#002a54',
          fixed: '#001c3b',
          'fixed-variant': '#1d477c',
        },
        error: {
          DEFAULT: '#ffb4ab',
          container: '#93000a',
        },
        'on-error': {
          DEFAULT: '#690005',
          container: '#ffdad6',
        },
        background: '#101416',
        'on-background': '#e0e3e6',
      },
      fontFamily: {
        display: ['"IBM Plex Sans"', 'sans-serif'],
        headline: ['"IBM Plex Sans"', 'sans-serif'],
        sans: ['"Inter"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      borderRadius: {
        'sm': '0.25rem',
        DEFAULT: '0.5rem',
        'md': '0.75rem',
        'lg': '1rem',
        'xl': '1.5rem',
        'full': '9999px',
      },
      spacing: {
        'sidebar': '260px',
        'sidebar-collapsed': '64px',
        'header': '64px',
      }
    },
  },
  plugins: [],
}
