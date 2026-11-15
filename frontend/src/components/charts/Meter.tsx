import type { LevelMeta } from '../../severity'
import { TONE_BG, TONE_TRACK } from '../../severity'

/** One ratio against a limit: fill in the state's tone on a same-tone track. */
export function Meter({ value, max, meta, label }: { value: number; max: number; meta: LevelMeta; label: string }) {
  const share = Math.max(0, Math.min(1, value / max))
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={value}
      className={`relative h-2 w-full overflow-hidden rounded-full ${TONE_TRACK[meta.tone]}`}
    >
      <div className={`h-full rounded-full ${TONE_BG[meta.tone]}`} style={{ width: `${share * 100}%` }} />
    </div>
  )
}
