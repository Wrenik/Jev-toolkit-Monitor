// Pure decision logic for jev-monitor: no I/O, so it can be unit tested.
// The Python server owns the rules, the policy and the log. This file only decides what the
// mod does with the server's answer, and what to do when there is no answer.

export type ToolClass = 'read' | 'write' | 'shell' | 'network' | 'mcp' | 'agent' | 'other'
export type Mode = 'monitor' | 'enforce'

export interface CheckResponse {
  ok: boolean
  error?: string
  action?: 'allow' | 'log' | 'warn' | 'ask' | 'block' | 'kill'
  would?: string
  mode?: Mode
  class?: ToolClass
  reason?: string
  rules?: string[]
  severity?: string
  skipped?: boolean
}

// What the server last told us. Used when the server cannot be reached, so a restart of the
// server (or of this session) does not silently drop an enforcing policy.
export interface FailTable {
  mode: Mode
  classModes: Partial<Record<ToolClass, Mode>>
  fail: Record<ToolClass, 'closed' | 'open'>
  // true when the opt-in check of tool results and MCP tool descriptions is on (the server says so in /health)
  results?: boolean
}

export const DEFAULT_TABLE: FailTable = {
  mode: 'monitor',
  classModes: {},
  fail: { read: 'open', write: 'closed', shell: 'closed', network: 'closed', mcp: 'closed', agent: 'closed', other: 'open' },
}

const READ = new Set(['Read', 'Grep', 'Glob', 'LS', 'NotebookRead', 'ToolSearch', 'TodoWrite', 'TaskList', 'TaskGet'])
const WRITE = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit'])
const SHELL = new Set(['Bash', 'PowerShell', 'BashOutput', 'KillShell', 'KillBash'])
const NETWORK = new Set(['WebFetch', 'WebSearch'])
const AGENT = new Set(['Agent', 'Task'])

export function toolClass(tool: string): ToolClass {
  if (READ.has(tool)) return 'read'
  if (WRITE.has(tool)) return 'write'
  if (SHELL.has(tool)) return 'shell'
  if (NETWORK.has(tool)) return 'network'
  if (tool.startsWith('mcp__')) return 'mcp'
  if (AGENT.has(tool)) return 'agent'
  return 'other'
}

// Keys of a tool.call event that are the engine's, not the tool's arguments.
const RESERVED = new Set(['tool', 'tool_use_id', 'agentId', 'requestMeta', 'consent'])

export function inputOf(e: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(e)) if (!RESERVED.has(k)) out[k] = v
  return out
}

export function modeFor(table: FailTable, cls: ToolClass): Mode {
  return table.classModes[cls] ?? table.mode
}

export function updateTable(table: FailTable, r: CheckResponse): FailTable {
  if (!r.ok || !r.class || !r.mode) return table
  return { ...table, classModes: { ...table.classModes, [r.class]: r.mode } }
}

export type Verdict =
  | { kind: 'pass'; log?: string }
  | { kind: 'note'; text: string; toast?: string }
  | { kind: 'deny'; text: string; toast: string }
  | { kind: 'kill'; text: string; toast: string }

function oneLine(s: string, n = 160): string {
  const t = (s.split('\n')[0] ?? s).replace(/\s+/g, ' ').trim()
  return t.length > n ? `${t.slice(0, n - 3)}...` : t
}

// The single place that maps a server answer (or its absence) to what happens to the call.
export function decide(tool: string, r: CheckResponse | null, table: FailTable): Verdict {
  const cls = toolClass(tool)
  if (r === null || !r.ok || !r.action) {
    const why = r?.error ?? 'monitor server unreachable'
    if (modeFor(table, cls) === 'enforce' && table.fail[cls] === 'closed') {
      return {
        kind: 'deny',
        text: `jev-monitor could not check this ${tool} call (${why}) and ${cls} tools fail closed while enforcing. Tell the user the monitor is down; they can run /jevmonitor, or switch mode with \`python -m jev_monitor mode monitor\`.`,
        toast: `jev-monitor: ${tool} refused, monitor unavailable (${why}).`,
      }
    }
    return { kind: 'pass', log: `jev-monitor: ${tool} not checked (${why}); allowed (${cls} fails open${modeFor(table, cls) === 'monitor' ? ' in monitor mode' : ''}).` }
  }
  const reason = r.reason ?? ''
  switch (r.action) {
    case 'allow':
    case 'log':
      return { kind: 'pass' }
    case 'warn': {
      const loud = r.would === 'ask' || r.would === 'block' || r.would === 'kill'
      return { kind: 'note', text: reason, toast: loud ? `jev-monitor (monitor mode): ${tool} would be ${r.would === 'kill' ? 'stopped' : r.would === 'ask' ? 'held' : 'blocked'}: ${oneLine(reason)}` : undefined }
    }
    case 'ask':
    case 'block':
      return { kind: 'deny', text: reason, toast: `jev-monitor ${r.action === 'ask' ? 'held' : 'blocked'} ${tool}: ${oneLine(reason)} /jevmonitor allow lets this exact call through once.` }
    case 'kill':
      return { kind: 'kill', text: reason, toast: `jev-monitor STOPPED the agent: ${oneLine(reason)} Clear it with /jevmonitor reset.` }
  }
  return { kind: 'pass' }
}

// Opt-in: the verdict on a tool RESULT (text the agent is about to read). The tool has already run, so the worst answer is to
// withhold its result; a failed or skipped check never blocks anything.
export function resultVerdict(tool: string, r: CheckResponse | null): Verdict {
  if (r === null || !r.ok || r.skipped || !r.action) return { kind: 'pass' }
  const reason = r.reason ?? ''
  if (r.action === 'block' || r.action === 'ask' || r.action === 'kill') {
    return { kind: 'deny', text: reason, toast: `jev-monitor withheld the result of ${tool}: ${oneLine(reason)}` }
  }
  if (r.action === 'warn' && reason) return { kind: 'note', text: reason, toast: undefined }
  return { kind: 'pass' }
}

// A short stable hash so a tool description is judged once per version, not on every render.
export function hashText(s: string): string {
  let h = 5381
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0
  return `${s.length}:${(h >>> 0).toString(16)}`
}

// The failure handler cannot wait for the server (it has a short grace), so it uses the table only.
export function failureVerdict(tool: string, table: FailTable): Verdict {
  const cls = toolClass(tool)
  if (modeFor(table, cls) === 'enforce' && table.fail[cls] === 'closed') {
    return { kind: 'deny', text: `jev-monitor's hook failed while checking ${tool}; ${cls} tools fail closed while enforcing. Tell the user.`, toast: `jev-monitor: hook failed, ${tool} refused.` }
  }
  return { kind: 'pass', log: `jev-monitor: hook failed for ${tool}; allowed (${cls} fails open${modeFor(table, cls) === 'monitor' ? ' in monitor mode' : ''}).` }
}

export function statusText(h: any, table: FailTable, extra: { python: string; off: boolean; last: string }): string {
  const up = h?.ok
  return [
    `mode: ${up ? h.mode : table.mode}${extra.off ? ' — mod switched OFF (/jevmonitor on)' : ''}   (/jevmonitor mode monitor|enforce)`,
    `server: ${up ? `up, judge ${h.judge ?? 'none'}${h.latched ? ' — LATCHED (/jevmonitor reset)' : ''}${h.stale ? ' — STALE, restart it' : ''}` : 'DOWN: sensitive tool calls ' + (table.mode === 'enforce' ? 'are refused (enforce mode)' : 'are allowed with a log line (monitor mode)')}`,
    `per-class: ${(['shell', 'write', 'network', 'mcp', 'agent', 'read'] as ToolClass[]).map((c) => `${c}=${modeFor(table, c)}/${table.fail[c]}`).join(' ')}`,
    `server python: ${extra.python} (data in JEV_HOME, default ~/.jev-toolkit)`,
    `last: ${extra.last}`,
    'what it watches: the AGENT\'s tool calls. Your own prompts and slash commands are never blocked. It reduces risk; it does not make an agent safe.',
    'privacy: with a Jev key, inconclusive calls are sent to the judge as a redacted one-line summary (judge.enabled = false in the policy keeps everything local).',
  ].join('\n')
}
