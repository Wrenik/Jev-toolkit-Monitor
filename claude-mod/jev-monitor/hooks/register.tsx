import type { Register } from 'claude-code'

import { DEFAULT_TABLE, decide, failureVerdict, inputOf, statusText, updateTable } from './logic'
import type { CheckResponse, FailTable } from './logic'

// jev-monitor: every tool call the AGENT makes goes to the local jev_monitor server before it runs.
// The server owns the rules, the policy, the kill latch and the log; this mod only acts on its answer.
// Your own prompts and slash commands never pass through the monitor, so it cannot lock you out.

const BASE = 'http://127.0.0.1:8767'
const HEADERS = { 'X-Jev-Monitor': '1', 'Content-Type': 'application/json' }
// Rules answer in milliseconds; a judge second opinion may add up to ~3.5 s (the hook's own clock stops during it).
const TIMEOUT_MS = 6000
const MAX_PROMPT_CHARS = 2000

let pythonOption = ''
let isStarting = false
let table: FailTable = { ...DEFAULT_TABLE }
let lastNote = 'nothing checked yet'
let mainTurnId: string | null = null
// After spawning the server the first call may arrive before it listens: wait for it once, not on every call.
let bootWaited = false
const BOOT_WAIT_MS = 5000
const BOOT_POLL_MS = 350

// How to start the server: the configured Python, else JEV_PYTHON, else PATH. Development fallback: when
// JEV_TOOLKIT points at a checkout with a .venv, that venv's Python is used and the server starts inside it.
async function launchOf($: any): Promise<{ python: string; cwd?: string }> {
  const isWindows = (await $.env.get('OS')) === 'Windows_NT'
  const configured = pythonOption || ((await $.env.get('JEV_PYTHON')) ?? '')
  if (configured) return { python: configured }
  const dev = ((await $.env.get('JEV_TOOLKIT')) ?? '').replace(/\\/g, '/').replace(/\/$/, '')
  if (dev) return { python: isWindows ? `${dev}/.venv/Scripts/python.exe` : `${dev}/.venv/bin/python`, cwd: dev }
  return { python: isWindows ? 'python' : 'python3' }
}

async function fetchJson($: any, path: string, init: any, ms: number): Promise<any> {
  const timeout = $.clock.sleep(ms).then(() => null)
  const response = await Promise.race([$.http.fetch(`${BASE}${path}`, { headers: HEADERS, ...init }), timeout])
  if (response === null) throw new Error(`timeout after ${ms} ms`)
  return JSON.parse(response.text)
}

async function saveTable($: any): Promise<void> {
  try {
    await $.store.set('table', JSON.stringify(table))
  } catch {
    /* the store is a convenience */
  }
}

async function loadTable($: any): Promise<void> {
  try {
    const saved = await $.store.get('table')
    if (typeof saved === 'string' && saved) table = { ...DEFAULT_TABLE, ...JSON.parse(saved) }
  } catch {
    /* keep defaults: monitor mode, sensitive classes closed once enforcing */
  }
}

async function health($: any): Promise<any> {
  try {
    const h = await fetchJson($, '/health', {}, 800)
    if (h?.ok) {
      table = { mode: h.mode, classModes: h.class_modes ?? {}, fail: { ...DEFAULT_TABLE.fail, ...(h.fail ?? {}) } }
      void saveTable($)
    }
    return h
  } catch {
    return null
  }
}

async function ensureServer($: any): Promise<void> {
  try {
    await startServer($)
  } catch {
    /* never an unhandled rejection: a server that will not start is reported by the fail table */
  }
}

async function startServer($: any): Promise<void> {
  if (isStarting || (await health($))?.ok) return
  isStarting = true
  try {
    const { python, cwd } = await launchOf($)
    const child = $.process.spawn({ argv: [python, '-m', 'jev_monitor', 'serve'], ...(cwd ? { cwd } : {}) })
    for await (const piece of child) {
      if (piece && typeof piece.text === 'string') $.ui.log(`jev-monitor server: ${piece.text.trim()}`, { to: 'debug' })
    }
  } catch (err) {
    $.ui.log(`jev-monitor: could not start the server: ${String((err as Error)?.message ?? err)}`)
  } finally {
    isStarting = false
  }
}

async function waitForServer($: any): Promise<boolean> {
  for (let waited = 0; waited < BOOT_WAIT_MS; waited += BOOT_POLL_MS) {
    if ((await health($))?.ok) return true
    await $.clock.sleep(BOOT_POLL_MS)
  }
  return false
}

async function ask($: any, e: any): Promise<CheckResponse | null> {
  const first = await tryCheck($, e)
  if (first !== null) {
    bootWaited = false
    return first
  }
  if (bootWaited) {
    void ensureServer($)
    return null
  }
  bootWaited = true
  void ensureServer($) // starts it if it is not up
  return (await waitForServer($)) ? tryCheck($, e) : null
}

async function tryCheck($: any, e: any): Promise<CheckResponse | null> {
  try {
    const body = {
      tool: e.tool,
      input: inputOf(e),
      cwd: await $.session.cwd(),
      root: await $.session.root(),
      session: await $.session.id(),
      agent_id: e.agentId,
    }
    return await fetchJson($, '/check', { method: 'POST', body: JSON.stringify(body) }, TIMEOUT_MS)
  } catch {
    return null
  }
}

async function control($: any, path: string, body: object): Promise<any | null> {
  try {
    return await fetchJson($, path, { method: 'POST', body: JSON.stringify({ session: await $.session.id(), ...body }) }, 4000)
  } catch {
    return null
  }
}

export const register: Register = (on, options) => {
  pythonOption = String((options as any)?.python ?? '')

  on('session.start', async ($, e, next) => {
    const started = await next(e)
    await loadTable($)
    $.command.register({ name: 'jevmonitor', description: 'jev-monitor: status, mode monitor|enforce, allow, reset, report, off|on' })
    void ensureServer($)
    return started
  })

  // The id of the running main-loop turn: the kill rung aborts it.
  on('turn.start', async ($, e, next) => {
    if ((e as any).agentId === undefined) mainTurnId = String((e as any).turnId ?? '')
    return next(e)
  }).catch(($, e, next) => next(e))

  // The point of the whole mod: the agent's tool call, before it runs.
  on('tool.call', async ($, e, next) => {
    if ((await $.store.get('off')) === 'yes') return next(e)
    const r = await ask($, e)
    if (r) table = updateTable(table, r)
    const v = decide(String((e as any).tool), r, table)
    lastNote = `${(e as any).tool}: ${r?.action ?? 'no answer'}${r?.rules?.length ? ` [${r.rules.join(',')}]` : ''}`
    if (v.kind === 'pass') {
      if (v.log) $.ui.log(v.log)
      return next(e)
    }
    if (v.kind === 'deny' || v.kind === 'kill') {
      $.ui.toast(v.toast)
      if (v.kind === 'kill' && mainTurnId) {
        try {
          await $.turn.abort({ turnId: mainTurnId })
        } catch {
          /* the deny below still holds */
        }
      }
      return { deny: v.text }
    }
    if (v.toast) $.ui.toast(v.toast)
    const result: any = await next(e)
    if (result && 'result' in result && v.text) return { ...result, context: [...(result.context ?? []), v.text] }
    return result
  }).catch(($, e, next) => {
    // The hook itself failed. A failed guard is skipped by the engine, so closed classes must be refused here.
    const v = failureVerdict(String((e as any).tool), table)
    if (v.kind === 'deny') return next.called ? next(e) : { deny: v.text }
    return next(e)
  })

  // Typed prompts: the task intent for the second opinion. Never blocked, never rewritten, sent only to the local server.
  on('prompt.submit', async ($, e, next) => {
    if (!e.command && !(e as any).isMeta && ['composer', 'sdk', 'bridge'].includes(String((e as any).origin?.kind)) && (await $.store.get('off')) !== 'yes') {
      void control($, '/intent', { text: String(e.text).slice(0, MAX_PROMPT_CHARS) })
    }
    return next(e)
  }).catch(($, e, next) => next(e))

  on('command.run', { command: 'jevmonitor' }, async ($, e, next) => {
    const [word, arg] = e.args.trim().split(/\s+/)
    if (word === 'off' || word === 'on') {
      await $.store.set('off', word === 'off' ? 'yes' : 'no')
      return { text: `jev-monitor: ${word === 'off' ? 'OFF — tool calls are NOT checked until /jevmonitor on' : 'on'}` }
    }
    if (word === 'mode') {
      if (arg !== 'monitor' && arg !== 'enforce') return { text: 'usage: /jevmonitor mode monitor|enforce' }
      const r = await control($, '/mode', { mode: arg })
      if (!r?.ok) return { text: `could not reach the monitor server. Run: python -m jev_monitor mode ${arg}` }
      void health($)
      return { text: `jev-monitor mode: ${arg}${arg === 'enforce' ? ' (blocks and kills are now real; /jevmonitor report shows what it would have stopped so far)' : ' (log and warn only)'}` }
    }
    if (word === 'reset') {
      const r = await control($, '/reset', {})
      return { text: r?.ok ? (r.was_latched ? 'jev-monitor: latch cleared, the agent may use tools again.' : 'jev-monitor: it was not latched.') : 'could not reach the server. From any terminal run: python -m jev_monitor reset' }
    }
    if (word === 'allow') {
      const r = await control($, '/allow', {})
      return { text: r?.ok ? 'jev-monitor: the last held call is allowed once (logged). Ask Claude to retry exactly that call.' : 'jev-monitor: nothing to allow (no held call, too many overrides, or a critical finding that cannot be overridden).' }
    }
    if (word === 'report') {
      const r = await control($, '/report', {})
      return { text: r?.ok ? String(r.text) : 'could not reach the server. Run: python -m jev_monitor report' }
    }
    const h = await health($)
    return { text: statusText(h, table, { python: (await launchOf($)).python, off: (await $.store.get('off')) === 'yes', last: lastNote }) }
  })
}
