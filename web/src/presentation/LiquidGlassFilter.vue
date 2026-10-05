<template>
  <!-- Adapted from WXperia's standard GlassFilter pipeline; the displacement field is generated locally. -->
  <svg class="liquid-glass-filter-definitions" aria-hidden="true">
    <defs>
      <filter id="admin-button-liquid-glass" x="-35%" y="-35%" width="170%" height="170%" color-interpolation-filters="sRGB">
        <feTurbulence type="fractalNoise" baseFrequency="0.004 0.012" numOctaves="1" seed="6" result="DISPLACEMENT_MAP" />
        <feDisplacementMap in="SourceGraphic" in2="DISPLACEMENT_MAP" scale="3" xChannelSelector="R" yChannelSelector="G" />
      </filter>
    </defs>
  </svg>
</template>
