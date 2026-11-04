import { expect, test } from 'claude-code/testing'

import { DEFAULT_TABLE, decide, failureVerdict, inputOf, modeFor, toolClass, updateTable } from './logic'
import type { FailTable } from './logic'

const enforcing: FailTable = { ...DEFAULT_TABLE, mode: 'enforce' }

test('maps tools to classes like the server does', async () => {
  expect(toolClass('Bash')).toBe('shell')
  expect(toolClass('PowerShell')).toBe('shell')
  expect(toolClass('Edit')).toBe('write')
  expect(toolClass('WebFetch')).toBe('network')
  expect(toolClass('mcp__github__get_issue')).toBe('mcp')
  expect(toolClass('Read')).toBe('read')
  expect(toolClass('Agent')).toBe('agent')
  expect(toolClass('SomethingNew')).toBe('other')
})

test('the tool arguments are the event minus the engine\'s own keys', async () => {
  expect(inputOf({ tool: 'Bash', tool_use_id: 't', agentId: 'a', requestMeta: {}, command: 'ls', timeout: 5 })).toEqual({ command: 'ls', timeout: 5 })
})

test('allow and log pass; warn adds a note and stays quiet unless it would have been blocked', async () => {
  expect(decide('Bash', { ok: true, action: 'allow' }, enforcing)).toEqual({ kind: 'pass' })
  expect(decide('Bash', { ok: true, action: 'log' }, enforcing)).toEqual({ kind: 'pass' })
  const quiet = decide('WebFetch', { ok: true, action: 'warn', would: 'warn', reason: 'note' }, enforcing)
  expect(quiet).toEqual({ kind: 'note', text: 'note', toast: undefined })
  const loud = decide('Bash', { ok: true, action: 'warn', would: 'block', reason: 'x' }, DEFAULT_TABLE)
  expect(loud.kind === 'note' && loud.toast).toContain('would be blocked')
})

test('block and ask become a deny that names the override; kill is its own verdict', async () => {
  const b = decide('Bash', { ok: true, action: 'block', reason: 'jev-monitor blocked Bash: x' }, enforcing)
  expect(b.kind).toBe('deny')
  if (b.kind === 'deny') expect(b.toast).toContain('/jevmonitor allow')
  expect(decide('Bash', { ok: true, action: 'ask', reason: 'held' }, enforcing).kind).toBe('deny')
  expect(decide('Bash', { ok: true, action: 'kill', reason: 'stopped' }, enforcing).kind).toBe('kill')
})

test('no answer: sensitive classes fail closed ONLY while enforcing, harmless ones and monitor mode fail open', async () => {
  expect(decide('Bash', null, enforcing).kind).toBe('deny')
  expect(decide('Edit', null, enforcing).kind).toBe('deny')
  expect(decide('WebFetch', { ok: false, error: 'internal' }, enforcing).kind).toBe('deny')
  expect(decide('Read', null, enforcing).kind).toBe('pass')
  const open = decide('Bash', null, DEFAULT_TABLE)
  expect(open.kind === 'pass' && open.log).toContain('monitor mode')
})

test('a per-class mode from the server beats the global mode', async () => {
  const t = updateTable(DEFAULT_TABLE, { ok: true, class: 'shell', mode: 'enforce' })
  expect(modeFor(t, 'shell')).toBe('enforce')
  expect(modeFor(t, 'write')).toBe('monitor')
  expect(decide('Bash', null, t).kind).toBe('deny')
  expect(decide('Edit', null, t).kind).toBe('pass')
})

test('a hook failure is decided from the table alone', async () => {
  expect(failureVerdict('Bash', enforcing).kind).toBe('deny')
  expect(failureVerdict('Read', enforcing).kind).toBe('pass')
  expect(failureVerdict('Bash', DEFAULT_TABLE).kind).toBe('pass')
})
