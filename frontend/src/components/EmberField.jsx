import React, { useEffect, useRef } from 'react'
import * as THREE from 'three'

/**
 * The ember field. A live 3D dependency web — hundreds of particles linked to
 * their nearest neighbours, drifting like dust in candlelight, with ONE hot
 * red ember pulsing deep inside it: the flaw nobody chose, buried in the
 * graph. The whole web leans toward your cursor. Decorative, but on-message.
 */

function dotTexture() {
  const c = document.createElement('canvas')
  c.width = c.height = 64
  const g = c.getContext('2d')
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32)
  grad.addColorStop(0, 'rgba(255,255,255,1)')
  grad.addColorStop(0.35, 'rgba(255,255,255,.7)')
  grad.addColorStop(1, 'rgba(255,255,255,0)')
  g.fillStyle = grad
  g.fillRect(0, 0, 64, 64)
  return new THREE.CanvasTexture(c)
}

export default function EmberField() {
  const box = useRef(null)

  useEffect(() => {
    const el = box.current
    if (!el || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(50, el.clientWidth / Math.max(el.clientHeight, 1), 0.1, 100)
    camera.position.z = 24
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: false })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5))
    renderer.setSize(el.clientWidth, el.clientHeight)
    renderer.domElement.style.cssText = 'position:absolute;inset:0;width:100%;height:100%'
    el.appendChild(renderer.domElement)

    const group = new THREE.Group()
    scene.add(group)

    /* ── particles: mostly quiet silver, a few sparks of gold and ember ── */
    const N = 220
    const base = new Float32Array(N * 3)
    const pos = new Float32Array(N * 3)
    const col = new Float32Array(N * 3)
    const seed = new Float32Array(N)
    const palette = [
      new THREE.Color('#b9b1a5'), new THREE.Color('#b9b1a5'), new THREE.Color('#8d857a'),
      new THREE.Color('#ffc46b'), new THREE.Color('#ff7a3d'),
    ]
    for (let i = 0; i < N; i++) {
      const r = 8 + Math.random() * 8
      const th = Math.random() * Math.PI * 2
      const ph = Math.acos(2 * Math.random() - 1)
      base[i * 3]     = r * Math.sin(ph) * Math.cos(th)
      base[i * 3 + 1] = r * Math.sin(ph) * Math.sin(th) * 0.55
      base[i * 3 + 2] = r * Math.cos(ph)
      seed[i] = Math.random() * Math.PI * 2
      const c = palette[(Math.random() * palette.length) | 0]
      col[i * 3] = c.r; col[i * 3 + 1] = c.g; col[i * 3 + 2] = c.b
    }
    pos.set(base)

    const tex = dotTexture()
    const geo = new THREE.BufferGeometry()
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3))
    geo.setAttribute('color', new THREE.BufferAttribute(col, 3))
    const mat = new THREE.PointsMaterial({
      size: 0.55, map: tex, vertexColors: true, transparent: true, opacity: 0.7,
      depthWrite: false, blending: THREE.AdditiveBlending, sizeAttenuation: true,
    })
    group.add(new THREE.Points(geo, mat))

    /* ── the web: each node linked to its two nearest neighbours ── */
    const links = []
    for (let i = 0; i < N; i++) {
      let b1 = -1, d1 = Infinity, b2 = -1, d2 = Infinity
      for (let j = 0; j < N; j++) {
        if (i === j) continue
        const dx = base[i * 3] - base[j * 3]
        const dy = base[i * 3 + 1] - base[j * 3 + 1]
        const dz = base[i * 3 + 2] - base[j * 3 + 2]
        const d = dx * dx + dy * dy + dz * dz
        if (d < d1) { d2 = d1; b2 = b1; d1 = d; b1 = j }
        else if (d < d2) { d2 = d; b2 = j }
      }
      links.push(i, b1, i, b2)
    }
    const lgeo = new THREE.BufferGeometry()
    lgeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(links.length * 3), 3))
    const lmat = new THREE.LineBasicMaterial({
      color: 0x8d857a, transparent: true, opacity: 0.1, blending: THREE.AdditiveBlending,
    })
    group.add(new THREE.LineSegments(lgeo, lmat))

    /* ── the flaw: one hot ember, pulsing, buried in the web ── */
    const FLAW = 3
    const fgeo = new THREE.BufferGeometry()
    fgeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(3), 3))
    const fmat = new THREE.PointsMaterial({
      size: 1.7, map: tex, color: 0xff4040, transparent: true,
      depthWrite: false, blending: THREE.AdditiveBlending,
    })
    group.add(new THREE.Points(fgeo, fmat))

    /* ── interaction: the web leans toward the cursor ── */
    let tx = 0, ty = 0, cx = 0, cy = 0
    const onMove = (e) => {
      const r = el.getBoundingClientRect()
      tx = (e.clientX - r.left) / Math.max(r.width, 1) - 0.5
      ty = (e.clientY - r.top) / Math.max(r.height, 1) - 0.5
    }
    window.addEventListener('pointermove', onMove)

    const ro = new ResizeObserver(() => {
      camera.aspect = el.clientWidth / Math.max(el.clientHeight, 1)
      camera.updateProjectionMatrix()
      renderer.setSize(el.clientWidth, el.clientHeight)
    })
    ro.observe(el)

    let raf
    const t0 = performance.now()
    const tick = () => {
      const t = (performance.now() - t0) / 1000
      cx += (tx - cx) * 0.05
      cy += (ty - cy) * 0.05
      group.rotation.y = t * 0.06 + cx * 0.7
      group.rotation.x = cy * 0.45

      const pa = geo.attributes.position.array
      for (let i = 0; i < N; i++) {
        pa[i * 3 + 1] = base[i * 3 + 1] + Math.sin(t * 1.5 + seed[i]) * 0.4
      }
      geo.attributes.position.needsUpdate = true

      const la = lgeo.attributes.position.array
      for (let k = 0; k < links.length; k++) {
        const n = links[k]
        la[k * 3] = pa[n * 3]; la[k * 3 + 1] = pa[n * 3 + 1]; la[k * 3 + 2] = pa[n * 3 + 2]
      }
      lgeo.attributes.position.needsUpdate = true

      const fa = fgeo.attributes.position.array
      fa[0] = pa[FLAW * 3]; fa[1] = pa[FLAW * 3 + 1]; fa[2] = pa[FLAW * 3 + 2]
      fgeo.attributes.position.needsUpdate = true
      fmat.size = 1.5 + Math.sin(t * 3) * 0.5
      fmat.opacity = 0.75 + Math.sin(t * 3) * 0.25

      renderer.render(scene, camera)
      raf = requestAnimationFrame(tick)
    }
    tick()

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('pointermove', onMove)
      ro.disconnect()
      geo.dispose(); lgeo.dispose(); fgeo.dispose()
      mat.dispose(); lmat.dispose(); fmat.dispose(); tex.dispose()
      renderer.dispose()
      el.removeChild(renderer.domElement)
    }
  }, [])

  return <div ref={box} className="pointer-events-none absolute inset-0" aria-hidden />
}
