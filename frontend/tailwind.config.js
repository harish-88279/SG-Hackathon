/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    // A deliberately SMALL, opinionated scale. Every value earns its place.
    fontSize: {
      micro: ['10.5px', { lineHeight: '1.4', letterSpacing: '0.09em', fontWeight: '600' }],
      xs:    ['11.5px', { lineHeight: '1.5' }],
      sm:    ['12.5px', { lineHeight: '1.55' }],
      base:  ['13.5px', { lineHeight: '1.65' }],
      md:    ['15px',   { lineHeight: '1.5', letterSpacing: '-0.006em' }],
      lg:    ['18px',   { lineHeight: '1.35', letterSpacing: '-0.012em' }],
      xl:    ['22px',   { lineHeight: '1.25', letterSpacing: '-0.016em' }],
      '2xl': ['28px',   { lineHeight: '1.18', letterSpacing: '-0.02em' }],
      '3xl': ['36px',   { lineHeight: '1.1',  letterSpacing: '-0.024em' }],
      '4xl': ['52px',   { lineHeight: '1',    letterSpacing: '-0.028em' }],
    },
    extend: {
      colors: {
        // Dark neutral ladder with a faint warm undertone. Charcoal, not orange.
        canvas:  '#0f0e0c',
        surface: '#171512',
        raised:  '#211e1a',
        hover:   '#292520',
        line:    '#2e2a24',   // hairline
        edge:    '#413b33',   // stronger edge

        ink:   '#f2eee7',     // primary text
        muted: '#b9b1a5',     // secondary
        dim:   '#847c6f',     // tertiary
        faint: '#544e44',     // quaternary / disabled

        sg:    '#ff7a3d',     // ember. The ONE accent.
        gold:  '#ffc46b',     // ember's gradient partner

        // Severity as a heat ramp. Danger literally glows hotter.
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
      borderRadius: { xs: '5px', DEFAULT: '9px', md: '12px', lg: '18px', xl: '24px' },
      boxShadow: {
        glass: '0 1px 0 0 rgba(255,220,180,.07) inset, 0 24px 60px -24px rgba(0,0,0,.55)',
        lift:  '0 1px 0 0 rgba(255,220,180,.12) inset, 0 32px 72px -24px rgba(0,0,0,.65), 0 0 60px -14px rgba(255,122,61,.45)',
        glow:  '0 0 34px -4px rgba(255,122,61,.8), 0 6px 24px -6px rgba(255,122,61,.5), 0 1px 0 rgba(255,255,255,.28) inset',
        pop:   '0 32px 80px -16px rgba(0,0,0,.75), 0 0 0 1px rgba(255,200,150,.09), 0 1px 0 rgba(255,220,180,.08) inset',
        drawer:'-32px 0 90px -16px rgba(0,0,0,.8)',
      },
      keyframes: {
        rise:   { from: { opacity: 0, transform: 'translateY(10px)' }, to: { opacity: 1, transform: 'none' } },
        slide:  { from: { transform: 'translateX(32px)', opacity: 0 }, to: { transform: 'none', opacity: 1 } },
        pop:    { from: { opacity: 0, transform: 'scale(.96) translateY(6px)' }, to: { opacity: 1, transform: 'none' } },
        pulseline: { '0%,100%': { opacity: .25 }