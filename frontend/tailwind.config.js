/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    fontSize: {
      micro: ['10.5px', { lineHeight: '1.4', letterSpacing: '0.08em', fontWeight: '600' }],
      xs:    ['11.5px', { lineHeight: '1.5' }],
      sm:    ['12.5px', { lineHeight: '1.55' }],
      base:  ['13.5px', { lineHeight: '1.65' }],
      md:    ['15px',   { lineHeight: '1.5', letterSpacing: '-0.006em' }],
      lg:    ['18px',   { lineHeight: '1.35', letterSpacing: '-0.012em' }],
      xl:    ['22px',   { lineHeight: '1.25', letterSpacing: '-0.018em' }],
      '2xl': ['30px',   { lineHeight: '1.16', letterSpacing: '-0.022em' }],
      '3xl': ['38px',   { lineHeight: '1.08', letterSpacing: '-0.028em' }],
      '4xl': ['54px',   { lineHeight: '1',    letterSpacing: '-0.032em' }],
    },
    extend: {
      colors: {
        // A WARM black. Neutral greys read as clinical; this reads as a lit room at night.
        canvas:  '#0f0e0c',
        deep:    '#0c0b0a',
        surface: '#131110',
        raised:  '#181614',
        hover:   '#1e1b18',
        line:    'rgba(255,255,255,.07)',
        edge:    'rgba(255,255,255,.13)',

        ink:   '#f2eee7',     // warm cream, not white
        muted: '#a89f92',
        dim:   '#847c6f',
        faint: '#5a5349',

        // ONE accent, and it is amber — not the obvious security-dashboard red.
        // Red everywhere is how a dashboard teaches you to ignore red.
        amber: {
          DEFAULT: '#ff7a3d',
          light:   '#ffb27a',
          gold:    '#ffc46b',
          deep:    '#e0501a',
        },

        crit: '#ff5d5d',
        high: '#ffa14d',
        med:  '#f2c94c',
        low:  '#82b4e8',
        ok:   '#5fcf9a',
        info: '#c9a6f7',
      },
      fontFamily: {
        display: ['"Bricolage Grotesque Variable"', '"Bricolage Grotesque"', 'system-ui', 'sans-serif'],
        sans: ['"Inter Variable"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono Variable"', 'ui-monospace', 'Menlo', 'monospace'],
      },
      borderRadius: { xs: '4px', DEFAULT: '7px', md: '10px', lg: '14px', xl: '20px', '2xl': '26px' },
      boxShadow: {
        amber: '0 8px 30px -8px rgba(255,122,61,.5), inset 0 1px 0 rgba(255,255,255,.28)',
        glow:  '0 0 40px -6px rgba(255,122,61,.35)',
        pop:   '0 20px 60px -14px rgba(0,0,0,.75), 0 0 0 1px rgba(255,255,255,.07)',
        card:  'inset 0 1px 0 rgba(255,255,255,.05)',
      },
      keyframes: {
        rise:  { from: { opacity: 0, transform: 'translateY(6px)' }, to: { opacity: 1, transform: 'none' } },
        slide: { from: { transform: 'translateX(26px)', opacity: 0 }, to: { transform: 'none', opacity: 1 } },
        pop:   { from: { opacity: 0, transform: 'scale(.97)' }, to: { opacity: 1, transform: 'none' } },
        sweep: { from: { transform: 'translateX(-100%)' }, to: { transform: 'translateX(100%)' } },
        twinkle: { '0%,100%': { opacity: .25 }, '50%': { opacity: .9 } },
      },
      animation: {
        rise:  'rise .34s cubic-bezier(.16,1,.3,1) both',
        slide: 'slide .34s cubic-bezier(.16,1,.3,1) both',
        pop:   'pop .16s cubic-bezier(.16,1,.3,1) both',
        sweep: 'sweep 1.5s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
